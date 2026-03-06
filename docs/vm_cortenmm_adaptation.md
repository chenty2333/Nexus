# Axle VM：CortenMM 适配说明

**更新时间**：2026-03-07

> 本文是对 `references/Axle_v0.3.md` 与
> `references/AxleKernel_Roadmap_v0.3.md` 的补充设计说明。  
> 它描述的是 **Axle 内部 VM 实现的迁移路径**，不直接更改当前对外 ABI /
> 对象语义合同。

---

## 1. 目标

Axle 希望吸收 CortenMM 最有价值的部分：

- 让页表修改统一走事务接口
- 让页级 metadata 成为 fault / COW / page-loan 的单一真相来源
- 保留 VMAR/VMO 作为对外控制面与对象语义边界
- 为后续 demand paging、true page-loan、recv remap、TLB batching 铺路

Axle **不**打算直接照搬 CortenMM 的完整终态。原因有三点：

- Axle 仍处于 bootstrap VM 阶段，当前还没有真正的多地址空间页表子系统
- Axle 的目标语义是 capability + VMAR/VMO + page-loan，而不是 Linux `mmap`
  兼容路径
- Axle 当前最紧迫的问题是“统一真相来源”，不是 day-1 性能极限

---

## 2. 当前状态

截至 2026-03-07，Axle 的 VM 路径仍是 bootstrap 形态：

- `axle-mm` 是 metadata-only 的 `VMO/VMAR/VMA` 层
- kernel 先改 `axle-mm` 元数据，再把结果同步到固定 `USER_PT`
- page fault 只处理 present+write 的 COW fault
- channel loan 只支持匿名、页对齐、已驻留页；read 端仍是 copyout

这意味着：

- `VMA` 仍是热路径查询入口
- `PTE` 只是由 metadata 推导出来的结果
- COW / fault / loan 的状态仍分散在多处

---

## 3. 适配原则

Axle 对 CortenMM 的适配遵循以下原则：

### 3.1 VMAR 不删除

VMAR 继续承担控制面职责：

- 地址区间管理
- 权限 ceiling
- destroy / revoke 的粗粒度枚举
- 对外对象语义边界

VMAR **不再应该成为** page fault / COW / page-loan 的最终热路径真相来源。

### 3.2 先统一页表修改入口

所有 PTE 修改路径应收口到统一事务接口。  
这是后续引入页级 metadata plane 的前提。

第一版后端可以继续包住当前 bootstrap `USER_PT` 直写路径，但接口本身应从一开始就长成：

- `lock(range) -> query / map / unmap / protect / commit`

也就是说，`commit` 是未来真正多地址空间页表、延迟 shootdown、批量同步的稳定边界；  
当前 bootstrap 后端即使仍然立即 flush，也不应把这种实现细节烙进长期 API 形状。

### 3.3 先引入粗粒度映射记录，再引入页级 metadata

Axle 采用两层结构：

- `MapRec`：粗粒度映射控制记录
- `PteMeta`：页级动态状态

在 `PteMeta` 到位前，现有 `Vma` 仍保留为兼容外壳。
但 `Vma` 不应长期继续承载可变页级真相；`MapRec` 落地后，应尽快把
`logical_write / COW / lazy / loan / pin` 等动态状态迁向 sidecar metadata。

### 3.4 不让 metadata 变胖

Axle 需要支持：

- demand paging
- COW
- page-loan
- physical / contiguous VMO
- pin / refcount / mapcount

因此页级 metadata 第一版必须保持极简，只放热路径必需字段。

---

## 4. 目标结构

目标中的 VM 内部结构如下。

### 4.1 VMAR tree：控制面

保留 VMAR tree，用于：

- 子区域关系
- 地址分配 / ASLR
- coarse mapping 生命周期
- destroy / revoke 枚举

### 4.2 MapRec：控制面与数据面的桥

每次 `vmar_map` 生成一个稳定的 coarse mapping record。

建议最小字段：

- `map_id`
- `owner_vmar_id`
- `vmo_id`
- `global_vmo_id`
- `base`
- `len`
- `vmo_offset`
- `max_perms`

`MapRec` 的职责是：

- 给页级 metadata 一个稳定的 coarse owner
- 支撑 future reverse lookup / page metadata linkage
- 避免把所有 coarse 信息复制进每个页表条目

### 4.3 PteMeta：页级动态状态

未来的页级 metadata plane 建议至少包含：

- `tag = Invalid | LazyAnon | LazyVmo | Present | Swapped | LoanFrag | Phys`
- `logical_write`
- `cow_shared`
- `pinned`
- `map_id`
- `page_delta`

其中：

- `logical_write` 表示语义上是否允许写
- 硬件 PTE 的 writable bit 只表示“当前是否放开写”
- 二者分离后，COW 与 page-loan 的状态机才能统一

在 Axle 的迁移路径里，`PteMeta` 第一版不需要 day-1 就绑定到硬件 PT page descriptor。  
先做 software shadow plane 是合理的，但键必须已经按：

- `(address_space, vpn)`

来建模，而不是按“当前 bootstrap `USER_PT` 的某个 index”建模。  
这样后续才能无痛替换为更接近 CortenMM 的 per-PT-page sidecar。

### 4.4 Frame descriptor：物理页层

per-PTE metadata 不能替代物理页描述符。  
Axle 仍需要一层 frame/page descriptor 维护：

- `refcount`
- `pin_count`
- `map_count`
- future `loan_count`
- future reverse-map anchor

这条线不应过度后置。  
当前 `FrameTable` 已经有 `ref_count / pin_count`，自然的下一步是把它逐步演化成更接近
`VmPageDesc` 的结构，而不是另起一套并行物理页元数据。

当前实现状态（2026-03-07）：

- `FrameTable` 已开始向 frame descriptor 形状演化
- descriptor 现在显式暴露 `map_count`
- `loan_count` 已接入 channel page-loan 生命周期
- frame descriptor 已开始维护一个最小 `rmap anchor`
- anchor 现在已带上 `address_space_id`
- `FrameTable` 现在开始维护 per-frame 的 reverse-mapping anchor 集合，而不是只存一个 best-effort anchor
- kernel 已能用这组 anchor 反查 live `(address_space, map_id, va)`，并把 channel `remap-fill -> COW split` 的映射基数打进 conformance telemetry
- 当前实现仍不是完整的 rmap 数据结构：它能回答“这帧当前有哪些已知映射 anchor”，但还没有按 frame 做高效删除/区间查询/批量失效

### 4.5 TxCursor：唯一页表修改入口

页表修改统一通过事务接口执行，例如：

- `query`
- `map`
- `unmap`
- `protect`

后续 fault / COW / page-loan / remap 全部应复用这条入口。

---

## 5. 分阶段迁移

### PR1：页表事务层收口

目标：

- 新增 `axle-page-table`
- 把 kernel 里直接改 `USER_PT` 的逻辑收口到 `TxCursor`

状态：

- 已完成

### PR2：MapId / MapRec 骨架

目标：

- 在 `axle-mm` 中引入稳定 `MapId`
- 为每个 coarse mapping 创建 `MapRec`
- 保留现有 `Vma` 作为兼容外壳

注意：

- 本阶段不迁移 COW state 到 `MapRec`
- 本阶段不引入 per-page metadata

### PR3：PteMetaStore 骨架

目标：

- 在每个 address space 引入最小页级 metadata store
- 第一版允许先做 software shadow plane，不强行上 radix tree
- 但索引必须按 `(address_space, vpn)` 建模
- 第一阶段仍允许使用 dense store，只要不把 bootstrap `USER_PT` index 暴露为长期接口

### PR4：fault / COW 迁移到页级 metadata

目标：

- 先让 fault 路径统一为“先查 metadata，再决定 protect / COW / not-present / lazy”
- 再把 COW 从 `VMA.copy_on_write` 迁到页级 metadata
- 最后再补 `not-present` fault 与 `LazyAnon`

bootstrap 阶段还有一个实现细节需要明确：  
由于当前仍是单地址空间 bring-up，kernel 自己对 user buffer 的 `copyin/copyout`
不会带着 userspace `PF_USER` fault 语义回来。  
因此在真正的多地址空间 fault-in 机制到位前，kernel 需要在直接访问 user range 前先做一次
software prefault / ensure-resident，把 `LazyAnon` 页 materialize 掉，并在需要时先解 COW。

### PR5：page-loan 深化

目标：

- sender / receiver 双地址空间事务
- recv-side remap-fill
- COW / loan / close / cancel 并发回归

建议拆成两步：

1. **先落 cross-aspace transaction 形状**
   - 在页表事务层之上增加 `TxSet` / address-space tx wrapper
   - 锁顺序按 `(address_space_id, range_base)` 固定
   - bootstrap 第一版允许只真正锁住“当前 address space”的页表窗口
   - 非当前 address space 的参与者先作为 deferred participant 进入事务集合
   - page-loan record 应携带 source `address_space_id`，避免后续继续依赖 ambient current process
2. **再补真正的数据面**
   - receiver recv-view 映射
   - remap-fill 快路径
   - close / cancel / read 并发回归

也就是说，PR5 的第一刀不是直接做 recv-side remap，  
而是先把“多地址空间事务的 API 形状和锁顺序”稳定下来。

当前实现状态（2026-03-07）：

- 已完成 cross-aspace transaction scaffold
- channel loan record 已携带 source / receiver `address_space_id`
- `channel_write` 已通过 sender / receiver 双参与者事务进入 sender-side COW arm
- `channel_read` 已增加 bootstrap `remap-fill` 快路径
- channel `close/read` 与 `WRITABLE` 恢复语义已由 conformance 固定

### PR6a：收掉 channel endpoint 的 create-time address-space snapshot

当前 channel endpoint 仍不应长期持有“创建时拍下来的 `owner_address_space_id`”。  
更稳的过渡形状是：

- endpoint 持有 `owner_process_id`
- 真正需要进入 loan/remap 事务时，再动态解析该 process 当前绑定的 `address_space_id`
- 在尚未支持跨进程 handle transfer 前，这已经足以消掉当前 bootstrap 假设

这一步是内部归因修正，不改变外部 channel 语义。

当前 `remap-fill` 仍是保守版本，限制为：

- 仅适用于 page-aligned / page-sized loan payload
- 仅适用于 receiver 侧“整段 exact mapping” 的匿名缓冲区
- receiver mapping 通过现有匿名 VMO frame rebind + RO+COW 元数据实现
- 不对非匿名目标、碎片消息、或跨 mapping buffer 做 remap；这些仍回退到 copyout

### PR6+：性能强化包

这些属于后续优化，而不是当前前置条件：

- per-PT-page descriptors
- reverse mapping
- upper-level uniform metadata
- lazy TLB shootdown
- per-core VA allocator

---

## 6. 明确的非目标

当前阶段明确 **不做**：

- 删除 VMAR / VMA
- 直接把全部状态搬进 per-PTE metadata
- 立即上 radix tree 作为 day-1 依赖
- 立即做 recv-side remap 取代 copyout
- 立即做 lazy shootdown / per-core VA allocator
- 立即把形式化验证当作实现前置条件

---

## 7. 与现有合同的关系

本文不修改以下外部合同：

- syscall ABI
- handle encoding
- rights / signals 语义
- `zx_channel_*` / `zx_vmar_*` / `zx_vmo_*` 的对外对象模型

若未来迁移导致外部可观察语义变化，必须先修改：

- `references/Axle_v0.3.md`
- `references/AxleKernel_Roadmap_v0.3.md`

---

## 8. 当前实现指引

在 `PteMeta` 到位之前，Axle 的实现策略应保持为：

- `VMAR`：控制面对象
- `MapRec`：稳定 coarse mapping identity
- `Vma`：兼容现有 reverse lookup / perms / COW 外壳
- `TxCursor`：唯一页表修改入口

也就是说，当前阶段的重点不是“删旧结构”，而是先把：

- coarse mapping identity
- page-table mutation entrypoint
- future page metadata landing zone

这三件事搭起来。

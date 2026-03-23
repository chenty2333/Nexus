use alloc::vec;

use axle_types::status::{ZX_ERR_ACCESS_DENIED, ZX_OK};
use libzircon::rights::{ZX_RIGHT_MAP, ZX_RIGHT_READ, ZX_RIGHT_WRITE};
use libzircon::vmo::{ZX_VMO_BACKING_SCOPE_GLOBAL_SHARED, ZX_VMO_KIND_ANONYMOUS, zx_vmo_info_t};
use libzircon::{ax_vmo_get_info, zx_handle_close, zx_vmo_read, zx_vmo_set_size, zx_vmo_write};
use nexus_io::{OpenFlags, VmoFlags};

use crate::{ROOT_DECL_VMO_SHARED_BYTES, build_bootstrap_namespace, write_slot};

const SLOT_VMO_STAGED_PRESENT: usize = 1053;
const SLOT_VMO_STAGED_FAILURE_STEP: usize = 1054;
const SLOT_VMO_STAGED_NAMESPACE_BUILD: usize = 1055;
const SLOT_VMO_STAGED_OPEN: usize = 1056;
const SLOT_VMO_STAGED_GET_VMO: usize = 1057;
const SLOT_VMO_STAGED_INFO: usize = 1058;
const SLOT_VMO_STAGED_INFO_KIND: usize = 1059;
const SLOT_VMO_STAGED_INFO_BACKING_SCOPE: usize = 1060;
const SLOT_VMO_STAGED_INFO_FLAGS: usize = 1061;
const SLOT_VMO_STAGED_INFO_SIZE: usize = 1062;
const SLOT_VMO_STAGED_INFO_SIZE_PAGE_ALIGNED: usize = 1063;
const SLOT_VMO_STAGED_READ: usize = 1064;
const SLOT_VMO_STAGED_READ_MATCH: usize = 1065;
const SLOT_VMO_STAGED_WRITE: usize = 1066;
const SLOT_VMO_STAGED_RESIZE: usize = 1067;

const STEP_NAMESPACE_BUILD: u64 = 1;
const STEP_OPEN: u64 = 2;
const STEP_GET_VMO: u64 = 3;
const STEP_INFO: u64 = 4;
const STEP_INFO_KIND: u64 = 5;
const STEP_READ: u64 = 6;
const STEP_WRITE: u64 = 7;
const STEP_RESIZE: u64 = 8;

const STAGED_SHARED_PATH: &str = "/boot/manifests/root-vmo-shared.nxcd";
const PAGE_BYTES: u64 = 4096;

#[derive(Clone, Copy, Default)]
struct StagedSharedVmoSummary {
    failure_step: u64,
    namespace_build: i64,
    open_status: i64,
    get_vmo_status: i64,
    info_status: i64,
    info_kind: u64,
    info_backing_scope: u64,
    info_flags: u64,
    info_size: u64,
    info_size_page_aligned: u64,
    read_status: i64,
    read_match: u64,
    write_status: i64,
    resize_status: i64,
}

pub(crate) fn run_root_shared_source_contract() -> i32 {
    let summary = run_shared_source_contract();
    write_summary(&summary);
    i32::from(summary.failure_step != 0)
}

fn run_shared_source_contract() -> StagedSharedVmoSummary {
    let mut summary = StagedSharedVmoSummary::default();
    let bootstrap = match build_bootstrap_namespace() {
        Ok(namespace) => {
            summary.namespace_build = ZX_OK as i64;
            namespace
        }
        Err(status) => {
            summary.namespace_build = status as i64;
            summary.failure_step = STEP_NAMESPACE_BUILD;
            return summary;
        }
    };

    let file = match bootstrap
        .namespace()
        .open(STAGED_SHARED_PATH, OpenFlags::READABLE)
    {
        Ok(file) => {
            summary.open_status = ZX_OK as i64;
            file
        }
        Err(status) => {
            summary.open_status = status as i64;
            summary.failure_step = STEP_OPEN;
            return summary;
        }
    };

    let vmo = match file.as_vmo(VmoFlags::READ) {
        Ok(vmo) => {
            summary.get_vmo_status = ZX_OK as i64;
            vmo
        }
        Err(status) => {
            summary.get_vmo_status = status as i64;
            summary.failure_step = STEP_GET_VMO;
            return summary;
        }
    };

    let mut info = zx_vmo_info_t::default();
    summary.info_status = ax_vmo_get_info(vmo, &mut info) as i64;
    summary.info_kind = info.kind as u64;
    summary.info_backing_scope = info.backing_scope as u64;
    summary.info_flags = info.flags as u64;
    summary.info_size = info.size_bytes;
    summary.info_size_page_aligned = u64::from(info.size_bytes % PAGE_BYTES == 0);
    if summary.info_status != ZX_OK as i64 {
        summary.failure_step = STEP_INFO;
        let _ = zx_handle_close(vmo);
        return summary;
    }
    if info.kind != ZX_VMO_KIND_ANONYMOUS
        || info.backing_scope != ZX_VMO_BACKING_SCOPE_GLOBAL_SHARED
        || (info.rights & (ZX_RIGHT_READ | ZX_RIGHT_MAP)) != (ZX_RIGHT_READ | ZX_RIGHT_MAP)
        || (info.rights & ZX_RIGHT_WRITE) != 0
        || info.size_bytes < ROOT_DECL_VMO_SHARED_BYTES.len() as u64
        || summary.info_size_page_aligned != 1
    {
        summary.failure_step = STEP_INFO_KIND;
        let _ = zx_handle_close(vmo);
        return summary;
    }

    let mut bytes = vec![0u8; ROOT_DECL_VMO_SHARED_BYTES.len()];
    summary.read_status = zx_vmo_read(vmo, &mut bytes, 0) as i64;
    summary.read_match = u64::from(bytes.as_slice() == ROOT_DECL_VMO_SHARED_BYTES);
    if summary.read_status != ZX_OK as i64 || summary.read_match != 1 {
        summary.failure_step = STEP_READ;
        let _ = zx_handle_close(vmo);
        return summary;
    }

    summary.write_status = zx_vmo_write(vmo, b"x", 0) as i64;
    if summary.write_status != ZX_ERR_ACCESS_DENIED as i64 {
        summary.failure_step = STEP_WRITE;
        let _ = zx_handle_close(vmo);
        return summary;
    }

    summary.resize_status = zx_vmo_set_size(vmo, info.size_bytes.saturating_add(PAGE_BYTES)) as i64;
    if summary.resize_status != ZX_ERR_ACCESS_DENIED as i64 {
        summary.failure_step = STEP_RESIZE;
    }

    let _ = zx_handle_close(vmo);
    summary
}

fn write_summary(summary: &StagedSharedVmoSummary) {
    write_slot(SLOT_VMO_STAGED_PRESENT, 1);
    write_slot(SLOT_VMO_STAGED_FAILURE_STEP, summary.failure_step);
    write_slot(
        SLOT_VMO_STAGED_NAMESPACE_BUILD,
        summary.namespace_build as u64,
    );
    write_slot(SLOT_VMO_STAGED_OPEN, summary.open_status as u64);
    write_slot(SLOT_VMO_STAGED_GET_VMO, summary.get_vmo_status as u64);
    write_slot(SLOT_VMO_STAGED_INFO, summary.info_status as u64);
    write_slot(SLOT_VMO_STAGED_INFO_KIND, summary.info_kind);
    write_slot(
        SLOT_VMO_STAGED_INFO_BACKING_SCOPE,
        summary.info_backing_scope,
    );
    write_slot(SLOT_VMO_STAGED_INFO_FLAGS, summary.info_flags);
    write_slot(SLOT_VMO_STAGED_INFO_SIZE, summary.info_size);
    write_slot(
        SLOT_VMO_STAGED_INFO_SIZE_PAGE_ALIGNED,
        summary.info_size_page_aligned,
    );
    write_slot(SLOT_VMO_STAGED_READ, summary.read_status as u64);
    write_slot(SLOT_VMO_STAGED_READ_MATCH, summary.read_match);
    write_slot(SLOT_VMO_STAGED_WRITE, summary.write_status as u64);
    write_slot(SLOT_VMO_STAGED_RESIZE, summary.resize_status as u64);
}

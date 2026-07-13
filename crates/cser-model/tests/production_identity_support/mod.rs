#![allow(dead_code)]

use cser_model::production_identity::{
    DMA_OWNER_COUNT, DomainId, EffectIdentity, OperationClass, ParentIdentity,
    ProductionIdentityModel, RegistryInstance, RootId,
};

#[derive(Clone, Copy)]
pub struct WorkloadIdentities {
    pub syscall: EffectIdentity,
    pub filesystem: EffectIdentity,
    pub block: EffectIdentity,
    pub dma_a: EffectIdentity,
    pub dma_b: EffectIdentity,
    pub dma_request: EffectIdentity,
}

impl WorkloadIdentities {
    pub const fn all(self) -> [EffectIdentity; 6] {
        [
            self.syscall,
            self.filesystem,
            self.block,
            self.dma_a,
            self.dma_b,
            self.dma_request,
        ]
    }

    pub const fn dma_owners(self) -> [EffectIdentity; DMA_OWNER_COUNT] {
        [self.dma_a, self.dma_b, self.dma_request]
    }

    pub const fn by_operation(self, operation: OperationClass) -> EffectIdentity {
        match operation {
            OperationClass::FilesystemSyscall => self.syscall,
            OperationClass::FilesystemRead => self.filesystem,
            OperationClass::BlockRequest => self.block,
            OperationClass::DmaQueueOwnerA => self.dma_a,
            OperationClass::DmaQueueOwnerB => self.dma_b,
            OperationClass::DmaRequestOwner => self.dma_request,
        }
    }
}

pub fn registered_model() -> (ProductionIdentityModel, WorkloadIdentities) {
    let mut model = ProductionIdentityModel::new(RegistryInstance::new(7), RootId::new(11), 3);
    let root = model.root_identity();
    let syscall = model
        .register_effect(
            root,
            model.binding(DomainId::Personality).unwrap(),
            OperationClass::FilesystemSyscall,
            ParentIdentity::Root(root.lineage()),
        )
        .unwrap();
    let filesystem = model
        .register_effect(
            root,
            model.binding(DomainId::Filesystem).unwrap(),
            OperationClass::FilesystemRead,
            ParentIdentity::Effect(syscall.key()),
        )
        .unwrap();
    let block = model
        .register_effect(
            root,
            model.binding(DomainId::VirtIo).unwrap(),
            OperationClass::BlockRequest,
            ParentIdentity::Effect(filesystem.key()),
        )
        .unwrap();
    let dma_a = model
        .register_effect(
            root,
            model.binding(DomainId::VirtIo).unwrap(),
            OperationClass::DmaQueueOwnerA,
            ParentIdentity::Effect(block.key()),
        )
        .unwrap();
    let dma_b = model
        .register_effect(
            root,
            model.binding(DomainId::VirtIo).unwrap(),
            OperationClass::DmaQueueOwnerB,
            ParentIdentity::Effect(block.key()),
        )
        .unwrap();
    let dma_request = model
        .register_effect(
            root,
            model.binding(DomainId::VirtIo).unwrap(),
            OperationClass::DmaRequestOwner,
            ParentIdentity::Effect(block.key()),
        )
        .unwrap();
    (
        model,
        WorkloadIdentities {
            syscall,
            filesystem,
            block,
            dma_a,
            dma_b,
            dma_request,
        },
    )
}

pub fn prepared_model() -> (ProductionIdentityModel, WorkloadIdentities) {
    let (mut model, identities) = registered_model();
    for identity in identities.all() {
        model
            .prepare_effect(model.binding(identity.domain()).unwrap(), identity)
            .unwrap();
    }
    (model, identities)
}

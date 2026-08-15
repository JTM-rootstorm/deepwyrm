#![allow(dead_code)]

pub(crate) mod frame_roles {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct BackingIdentity;

    impl BackingIdentity {
        pub(crate) const EMPTY: Self = Self;
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum ObjectBackingKind {
        AllocatorOwned,
        ImmutableModule { module_index: u32 },
    }

    #[derive(Debug, Eq, PartialEq)]
    pub(crate) struct ObjectBackingGrant;

    impl ObjectBackingGrant {
        pub(crate) const fn identity(&self) -> BackingIdentity {
            BackingIdentity
        }

        pub(crate) const fn physical_start(&self) -> u64 {
            0
        }

        pub(crate) const fn byte_len(&self) -> u64 {
            0
        }

        pub(crate) const fn kind(&self) -> ObjectBackingKind {
            ObjectBackingKind::AllocatorOwned
        }
    }
}

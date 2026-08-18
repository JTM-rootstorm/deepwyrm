pub(crate) mod object {
    use crate::object::{CreationRef, FinalRelease};

    pub(crate) struct MemoryObjectBinding(CreationRef);
    impl MemoryObjectBinding {
        pub(crate) fn into_creation(self) -> CreationRef { self.0 }
    }

    pub(crate) struct MemoryObjectCleanup(FinalRelease);
    impl MemoryObjectCleanup {
        pub(crate) fn into_final_release(self) -> FinalRelease { self.0 }
    }
}

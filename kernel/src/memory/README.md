# Memory boundary

The memory subsystem owns physical-frame roles, typed `MemoryObject` backing,
checked userspace ranges/copying, address-space identities, and transactional
`AddressRegion` mapping state. Generic object liveness remains in
`ObjectRegistry`; memory payloads preserve typed backing and mapping leases until
finalization rather than maintaining an independent reference count.

Process root address regions are adapted into generic rights-bearing objects by
a typed payload authority. Their external handles do not define address-space
lifetime: a root-region lifecycle pin survives while the owning Process can
execute, and typed teardown must remove mappings before retiring that pin.

Architecture page-table publication remains behind the sealed
`AddressSpacePublisher` boundary. Task state, scheduling policy, syscall
copyin/copyout orchestration, and userspace allocation policy are separate
consumers of these mechanisms.

# deepwyrm-abi

`deepwyrm-abi` is the future `no_std` consumer crate for definitions generated
from Deepwyrm's canonical ABI schema.

The bootstrap crate deliberately exports no ABI types, constants, values,
layouts, syscalls, or helpers. Its presence establishes only the package and
module boundary; it does not establish a kernel/userspace contract.

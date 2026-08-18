#![allow(dead_code)]

#[path = "frame_roles_stub.rs"]
mod memory;
#[path = "../../src/object/mod.rs"]
mod object;
#[path = "../../src/memory/vm.rs"]
mod vm;

use vm::object::MapAuthorization;

fn clone_authorization(authorization: &MapAuthorization) {
    let _ = <MapAuthorization as Clone>::clone(authorization);
}

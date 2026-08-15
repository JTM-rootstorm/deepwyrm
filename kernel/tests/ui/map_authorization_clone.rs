#![allow(dead_code)]

#[path = "../../src/memory/vm.rs"]
mod vm;

use vm::object::MapAuthorization;

fn clone_authorization(authorization: &MapAuthorization) {
    let _ = <MapAuthorization as Clone>::clone(authorization);
}

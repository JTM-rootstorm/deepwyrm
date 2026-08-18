//! Caller-local DW0-D handle table and generated-rights validation.

mod rights;
mod table;

#[allow(
    unused_imports,
    reason = "DW0-D3 exports the table API before DW0-D4/D5 consume it"
)]
pub(crate) use table::{
    AcceptedObjectTypes, BasicHandleInfo, DrainResult, HandleTable, HandleTableError, InstallError,
    ResolvedHandle,
};

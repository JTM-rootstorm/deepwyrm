use deepwyrm_abi::{DwObjectType, DwRights, dw_rights_are_compatible, dw_rights_are_known};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RightsValidationError {
    Zero,
    Unknown,
    Incompatible,
    Missing,
    Escalation,
}

pub(super) fn validate_requested_syntax(rights: DwRights) -> Result<(), RightsValidationError> {
    if rights.0 == 0 {
        return Err(RightsValidationError::Zero);
    }
    if !dw_rights_are_known(rights) {
        return Err(RightsValidationError::Unknown);
    }
    Ok(())
}
pub(super) fn validate_required_syntax(rights: DwRights) -> Result<(), RightsValidationError> {
    if !dw_rights_are_known(rights) {
        return Err(RightsValidationError::Unknown);
    }
    Ok(())
}

pub(super) fn validate_compatible(
    object_type: DwObjectType,
    rights: DwRights,
) -> Result<(), RightsValidationError> {
    if !dw_rights_are_compatible(object_type, rights) {
        return Err(RightsValidationError::Incompatible);
    }
    Ok(())
}

pub(super) fn require_held(
    held: DwRights,
    required: DwRights,
) -> Result<(), RightsValidationError> {
    if held.0 & required.0 != required.0 {
        return Err(RightsValidationError::Missing);
    }
    Ok(())
}
pub(super) fn require_subset(
    held: DwRights,
    requested: DwRights,
) -> Result<(), RightsValidationError> {
    if requested.0 & !held.0 != 0 {
        return Err(RightsValidationError::Escalation);
    }
    Ok(())
}

//! Bounded selector-local summaries of primordial terminal state.

use deepwyrm_abi::{
    DW_EXCEPTION_GENERAL_PROTECTION, DW_TASK_STATE_EXITED, DW_TERMINATION_NORMAL_EXIT,
    DW_TERMINATION_UNHANDLED_EXCEPTION, DwTaskTerminationInfoV1,
};

const fn primordial_application_summary(application_code: u32) -> u32 {
    if application_code == 0 {
        0
    } else if application_code == 0xaf01_0002 {
        // Wyrmroot system-init's fatal-reboot-required status is the primary
        // pre-bootstrap failure discriminator for these selectors.
        0x02
    } else if application_code & 0xffff_0000 == 0xaf01_0000 {
        0x10 | (application_code & 0x0f)
    } else if application_code & 0xffff_0000 == 0xaf11_0000 {
        0x20 | (application_code & 0x1f)
    } else if application_code & 0xffff_0000 == 0xaf1c_0000 {
        // Selector 29 preserves the bounded system-init pre-READY failure
        // category without exposing a production application-status ABI.
        0x20 | (application_code & 0x1f)
    } else if application_code & 0xff00_0000 == 0xb400_0000 {
        // B4 terminal records dedicate four bits each to the saturated
        // termination reason and exception type. Those two fields exactly
        // fill the selector's remaining summary byte; retaining fault class,
        // detail, or category too would make the diagnostic ambiguous.
        let reason = (application_code >> 18) & 0x0f;
        let exception_type = (application_code >> 14) & 0x0f;
        (reason << 4) | exception_type
    } else if application_code & 0xf000_0000 == 0xb000_0000 {
        // Preserve the bootstrap family plus its bounded low-six-bit reason.
        0x80 | (application_code & 0x3f)
    } else {
        0x40 | (application_code & 0x3f)
    }
}

pub(super) fn primordial_terminal_summary(info: Option<DwTaskTerminationInfoV1>) -> u32 {
    let Some(info) = info else {
        return 0xff;
    };
    if info.state != DW_TASK_STATE_EXITED {
        return 0xfc;
    }
    if info.reason == DW_TERMINATION_NORMAL_EXIT {
        primordial_application_summary(info.application_code)
    } else if info.reason == DW_TERMINATION_UNHANDLED_EXCEPTION {
        if info.exception_type == DW_EXCEPTION_GENERAL_PROTECTION {
            // C0..DF is unused by current normal/B4 summaries, other
            // exception types, and FC/FD/FF disposition markers. Its low five
            // bits retain invalid-return details 1..7 exactly and raw #GP
            // error codes through 31; larger architecture codes saturate.
            let detail = if info.detail > 0x1f {
                0x1f
            } else {
                info.detail
            };
            0xc0 | detail
        } else {
            // E0..EF retains every current generated exception type exactly
            // (or F for a future out-of-range value). Detail and fault class
            // cannot also fit without collapsing exception identities.
            let exception_type = if info.exception_type.0 > 0x0f {
                0x0f
            } else {
                info.exception_type.0
            };
            0xe0 | exception_type
        }
    } else {
        0xfd
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normal_exit(application_code: u32) -> DwTaskTerminationInfoV1 {
        DwTaskTerminationInfoV1 {
            state: DW_TASK_STATE_EXITED,
            reason: DW_TERMINATION_NORMAL_EXIT,
            application_code,
            ..Default::default()
        }
    }

    #[test]
    fn selector27_terminal_summary_preserves_af11_mapping_ordinals() {
        let mut observed = [0_u32; 12];
        for (index, summary) in observed.iter_mut().enumerate() {
            let ordinal = u32::try_from(index + 1).unwrap();
            *summary = primordial_terminal_summary(Some(normal_exit(0xaf11_0000 | ordinal)));
            assert_eq!(*summary, 0x20 | ordinal);
        }

        for (index, summary) in observed.iter().enumerate() {
            assert!(observed[..index].iter().all(|prior| prior != summary));
        }
    }

    #[test]
    fn selector29_terminal_summary_preserves_af1c_mapping_ordinals() {
        let mut observed = [0_u32; 31];
        for (index, summary) in observed.iter_mut().enumerate() {
            let ordinal = u32::try_from(index + 1).unwrap();
            *summary = primordial_terminal_summary(Some(normal_exit(0xaf1c_0000 | ordinal)));
            assert_eq!(*summary, 0x20 | ordinal);
        }

        for (index, summary) in observed.iter().enumerate() {
            assert!(observed[..index].iter().all(|prior| prior != summary));
        }
    }
}

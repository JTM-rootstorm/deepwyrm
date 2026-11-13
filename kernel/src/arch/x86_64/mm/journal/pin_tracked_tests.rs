//! DW2 §7.1 G1: the pin-tracked target's span rules, on the host.

use super::*;
use crate::memory::address_region::AddressSpaceKey;
use crate::memory::user_range::{EmptyAddressRule, UserAccess, UserAddressSpace, UserRange};
use crate::memory::usercopy::{UserPinError, UserPinTracker};

const PAGE: u64 = BASE_PAGE_SIZE;

fn space(raw: u64) -> AddressSpaceKey {
    AddressSpaceKey::for_test(1, raw)
}

fn word(address: u64) -> UserRange {
    UserRange::new(
        UserAddressSpace::x86_64_four_level(PAGE).unwrap(),
        address,
        4,
        4,
        UserAccess::READ,
        EmptyAddressRule::Reject,
    )
    .unwrap()
}

fn invalidate(pages: &[u64]) -> std::vec::Vec<VirtualPage> {
    pages
        .iter()
        .map(|page| VirtualPage::new(*page).unwrap())
        .collect()
}

#[test]
fn a_span_excludes_pins_until_it_ends_and_confines_its_batches() {
    let pins = UserPinTracker::<2>::new();
    let mut target = PinTrackedTarget {
        scratch: FakeTarget::default(),
        pins: &pins,
        address_space: space(1),
        span: None,
    };
    // A pin inside refuses the span; one outside does not.
    let inside = pins.pin_owned(space(1), word(PAGE * 20 + 8)).unwrap();
    assert_eq!(
        target.begin_mutation_span(PAGE * 16, PAGE * 8),
        Err(PinTrackedError::Pin(UserPinError::Conflict))
    );
    pins.release_owned(space(1), inside).unwrap();
    let outside = pins.pin_owned(space(1), word(PAGE * 40)).unwrap();
    target.begin_mutation_span(PAGE * 16, PAGE * 8).unwrap();
    // While it is held, no new pin enters it, and a second span is refused.
    assert!(pins.pin_owned(space(1), word(PAGE * 17)).is_err());
    assert_eq!(
        target.begin_mutation_span(PAGE * 30, PAGE),
        Err(PinTrackedError::Pin(UserPinError::Conflict))
    );
    // Batches inside it apply; one reaching past it is refused unapplied.
    target
        .apply(&[], &invalidate(&[PAGE * 16, PAGE * 23]))
        .unwrap();
    target.apply(&[], &invalidate(&[PAGE * 20])).unwrap();
    assert_eq!(
        target.apply(&[], &invalidate(&[PAGE * 22, PAGE * 24])),
        Err(PinTrackedError::Pin(UserPinError::InvalidMutationRange))
    );
    assert_eq!(target.scratch.apply_count, 2);
    target.end_mutation_span();
    // After it ends, pins may enter again, and a lone batch takes its own
    // permit: refused over a pin, applied elsewhere.
    let after = pins.pin_owned(space(1), word(PAGE * 17)).unwrap();
    assert_eq!(
        target.apply(&[], &invalidate(&[PAGE * 17])),
        Err(PinTrackedError::Pin(UserPinError::Conflict))
    );
    target.apply(&[], &invalidate(&[PAGE * 18])).unwrap();
    assert_eq!(target.scratch.apply_count, 3);
    pins.release_owned(space(1), after).unwrap();
    pins.release_owned(space(1), outside).unwrap();
}

#[test]
fn a_span_in_one_address_space_leaves_another_free() {
    let pins = UserPinTracker::<2>::new();
    let mut target = PinTrackedTarget {
        scratch: FakeTarget::default(),
        pins: &pins,
        address_space: space(1),
        span: None,
    };
    let other = pins.pin_owned(space(2), word(PAGE * 17)).unwrap();
    target.begin_mutation_span(PAGE * 16, PAGE * 8).unwrap();
    target.end_mutation_span();
    pins.release_owned(space(2), other).unwrap();
}

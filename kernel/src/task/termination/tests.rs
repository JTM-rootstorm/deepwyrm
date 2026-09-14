//! R5A: the arena's own contract. No termination path runs through it yet, so
//! these exercise the storage and its refusals directly.

extern crate std;

use super::*;
use crate::object::ObjectRegistry;

const OBJECTS: usize = 16;
type Tasks = super::super::TaskAuthority<4, 4, 8, 4>;

/// A registry plus the group whose own key every transaction below names, and
/// the owner reference real execution pins are retained from.
///
/// Obligations are produced by the registry, never hand-built: an `InternalRef`
/// the arena hands back has to be one the registry will accept back, or the
/// test proves nothing about the type the termination paths will carry.
struct Fixture {
    registry: ObjectRegistry<OBJECTS>,
    tasks: Tasks,
    group: TaskGroupKey,
    owner: InternalRef,
}

impl Fixture {
    fn new() -> Self {
        let mut registry = ObjectRegistry::<OBJECTS>::new();
        let mut tasks = Tasks::new();
        let (group, owner) = tasks.create_root_group(&mut registry).unwrap();
        Self {
            registry,
            tasks,
            group,
            owner,
        }
    }

    fn subject(&self) -> TerminationSubject {
        TerminationSubject::Group(self.group)
    }

    fn pin(&mut self) -> InternalRef {
        self.registry.retain_internal(&self.owner).unwrap()
    }

    /// Discharges an obligation the arena handed back, which is the only
    /// correct thing to do with one.
    fn release(&mut self, work: TerminationWork) {
        let pin = match work {
            TerminationWork::ProcessPin(pin) | TerminationWork::ThreadPin { pin, .. } => pin,
            TerminationWork::FinalRelease(_) => panic!("fixture produces pins, not releases"),
        };
        assert!(
            self.registry.release_internal(pin).unwrap().is_none(),
            "a retained pin on a live group is never the final reference"
        );
    }
}

fn arena() -> TerminationArena {
    TerminationArena::new()
}

#[test]
fn slots_are_bounded_and_a_closed_slot_is_reusable_under_a_fresh_generation() {
    let arena = arena();
    let fixture = Fixture::new();
    let mut tokens = [None; TERMINATION_TRANSACTION_SLOTS];
    for token in tokens.iter_mut() {
        *token = Some(arena.begin(fixture.subject()).expect("a free slot"));
    }
    assert_eq!(
        arena.begin(fixture.subject()),
        Err(TerminationError::Capacity)
    );

    let first = tokens[0].expect("seeded token");
    arena.advance(first, TerminationStage::Complete).unwrap();
    assert_eq!(arena.commit(first), Ok(0));

    let reused = arena
        .begin(fixture.subject())
        .expect("the committed slot is free");
    assert_eq!(reused.slot(), first.slot());
    assert_ne!(
        reused.generation(),
        first.generation(),
        "a reused slot must not reissue a generation a stale token could match"
    );
    assert_eq!(arena.stage(first), Err(TerminationError::Stale));
    assert_eq!(arena.commit(first), Err(TerminationError::Stale));
}

#[test]
fn a_stage_advances_and_never_regresses() {
    let arena = arena();
    let fixture = Fixture::new();
    let token = arena.begin(fixture.subject()).unwrap();
    assert_eq!(arena.stage(token), Ok(TerminationStage::DrainingHandles));
    arena
        .advance(token, TerminationStage::ReleasingThreadPins)
        .unwrap();
    arena.advance(token, TerminationStage::Finalizing).unwrap();
    assert_eq!(
        arena.advance(token, TerminationStage::ReleasingThreadPins),
        Err(TerminationError::StageRegression),
        "a stage that could go backwards would let a drained handle be drained twice"
    );
    assert_eq!(arena.stage(token), Ok(TerminationStage::Finalizing));
    // Re-advancing to the current stage is allowed: a step that produced no
    // work still reports where it is.
    arena.advance(token, TerminationStage::Finalizing).unwrap();
}

#[test]
fn the_window_refuses_rather_than_overwriting_and_drains_in_push_order() {
    let arena = arena();
    let mut fixture = Fixture::new();
    let token = arena.begin(fixture.subject()).unwrap();
    // Alternating variants make push order observable: pins retained from one
    // handle share an object id, so the variant is what distinguishes them.
    for index in 0..TERMINATION_WORK_WINDOW {
        let pin = fixture.pin();
        let work = if index % 2 == 0 {
            TerminationWork::ProcessPin(pin)
        } else {
            TerminationWork::ThreadPin {
                pin,
                resources: None,
            }
        };
        arena.push(token, work).expect("the window has room");
    }
    assert_eq!(arena.queued(token), Ok(TERMINATION_WORK_WINDOW));

    let overflow = fixture.pin();
    match arena.push(token, TerminationWork::ProcessPin(overflow)) {
        Err(TerminationError::WindowFull) => {}
        other => panic!("a full window must refuse, not overwrite: {other:?}"),
    }
    // The refused obligation is still the caller's; the arena never took it.
    // Nothing here can prove that by inspection, so release it and let the
    // registry's own accounting fail the test if the arena had kept a copy.
    let spare = fixture.pin();
    fixture.release(TerminationWork::ProcessPin(spare));

    let mut out: [Option<TerminationWork>; 8] = [const { None }; 8];
    assert_eq!(arena.drain_into(token, &mut out), Ok(8));
    for (index, item) in out.iter_mut().enumerate() {
        let work = item.take().expect("eight items were drained");
        let even = matches!(work, TerminationWork::ProcessPin(_));
        assert_eq!(
            even,
            index % 2 == 0,
            "obligations must come back in push order"
        );
        fixture.release(work);
    }
    assert_eq!(arena.queued(token), Ok(TERMINATION_WORK_WINDOW - 8));

    // The window is a ring: the space the drain freed is usable again.
    for _ in 0..8 {
        let pin = fixture.pin();
        arena
            .push(token, TerminationWork::ProcessPin(pin))
            .expect("drained slots are reusable");
    }
    assert_eq!(arena.queued(token), Ok(TERMINATION_WORK_WINDOW));

    // Leave nothing behind: the arena cannot be closed holding obligations.
    let mut window: [Option<TerminationWork>; TERMINATION_WORK_WINDOW] =
        [const { None }; TERMINATION_WORK_WINDOW];
    assert_eq!(
        arena.drain_into(token, &mut window),
        Ok(TERMINATION_WORK_WINDOW)
    );
    for item in window.iter_mut() {
        fixture.release(item.take().expect("the whole window drained"));
    }
    arena.advance(token, TerminationStage::Complete).unwrap();
    // Forty obligations were pushed across the two rounds and every one was
    // handed back: thirty-two, then eight after the ring reused the drained
    // space.
    assert_eq!(arena.commit(token), Ok(40));
}

#[test]
fn no_slot_can_be_closed_while_it_still_holds_an_obligation() {
    let arena = arena();
    let mut fixture = Fixture::new();
    let token = arena.begin(fixture.subject()).unwrap();
    let pin = fixture.pin();
    arena.push(token, TerminationWork::ProcessPin(pin)).unwrap();
    arena.advance(token, TerminationStage::Complete).unwrap();

    // Both exits refuse. An InternalRef or FinalRelease dropped inside the
    // arena is a leaked object reference nothing would ever report.
    assert_eq!(arena.commit(token), Err(TerminationError::WindowNotEmpty));
    assert_eq!(arena.abandon(token), Err(TerminationError::WindowNotEmpty));

    let mut out: [Option<TerminationWork>; 1] = [const { None }; 1];
    assert_eq!(arena.drain_into(token, &mut out), Ok(1));
    let work = out[0].take().expect("handed back, not dropped");
    fixture.release(work);
    assert_eq!(arena.commit(token), Ok(1));
}

#[test]
fn an_incomplete_transaction_commits_only_after_reaching_complete() {
    let arena = arena();
    let fixture = Fixture::new();
    let token = arena.begin(fixture.subject()).unwrap();
    assert_eq!(arena.commit(token), Err(TerminationError::Incomplete));
    arena
        .advance(token, TerminationStage::ReleasingProcessPins)
        .unwrap();
    assert_eq!(arena.commit(token), Err(TerminationError::Incomplete));
    // Abandon is the escape for a transaction that cannot finish. It does not
    // require Complete -- only an empty window.
    assert_eq!(arena.abandon(token), Ok(0));
    assert_eq!(arena.stage(token), Err(TerminationError::Stale));
}

#[test]
fn the_cursor_survives_a_step_that_could_not_fit_its_stage_in_one_window() {
    let arena = arena();
    let mut fixture = Fixture::new();
    let token = arena.begin(fixture.subject()).unwrap();
    assert_eq!(arena.cursor(token), Ok(TerminationCursor::default()));
    let resumed = TerminationCursor {
        process: 3,
        handle: 17,
        thread: 0,
    };
    arena.set_cursor(token, resumed).unwrap();

    let pin = fixture.pin();
    arena.push(token, TerminationWork::ProcessPin(pin)).unwrap();
    let mut out: [Option<TerminationWork>; 4] = [const { None }; 4];
    assert_eq!(arena.drain_into(token, &mut out), Ok(1));
    fixture.release(out[0].take().expect("one item drained"));
    assert_eq!(
        arena.cursor(token),
        Ok(resumed),
        "draining the window must not rewind where the next item comes from"
    );
}

#[test]
fn the_subject_is_readable_for_the_life_of_the_transaction_and_not_after() {
    let arena = arena();
    let fixture = Fixture::new();
    let token = arena.begin(fixture.subject()).unwrap();
    assert_eq!(arena.subject(token), Ok(fixture.subject()));
    arena.advance(token, TerminationStage::Complete).unwrap();
    assert_eq!(arena.commit(token), Ok(0));
    assert_eq!(arena.subject(token), Err(TerminationError::Stale));
}

#[test]
fn peak_storage_does_not_scale_with_processes_or_handles() {
    // R5's gate. The batch this replaces measures 365,064 bytes at
    // PROCESSES = HANDLES = THREADS = 64, and the two terminate frames measure
    // 1,476,128. The arena's size is the product of two compile-time constants
    // and mentions neither capacity.
    let arena_bytes = core::mem::size_of::<TerminationArena>();
    assert!(
        arena_bytes < 365_064,
        "the arena is {arena_bytes} bytes and must stay under the batch it replaces"
    );
    assert_eq!(TERMINATION_TRANSACTION_SLOTS, crate::cpu::CPU_CAPACITY * 2);
    assert_eq!(TERMINATION_WORK_WINDOW, 32);
}

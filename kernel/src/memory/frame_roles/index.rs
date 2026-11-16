//! On-demand object backing: a per-object radix index (DW2 M6 §8.3).
//!
//! The backing is a tree of 512-entry node pages keyed by object page,
//! sized at creation to the object (at most four levels). The root node
//! holds the backing's identity. An entry is the raw role identity of a
//! child node or, at level 0, of a committed page; zero is empty, and no
//! identity is zero. Every step checks the entry's role against the root
//! (`owner`) and the place it must hold, so a stale, foreign or misplaced
//! entry fails as a chain walk does. Pages and nodes are added only through
//! `&mut self`, each zeroed before any entry names it.

use super::*;

/// Entries per index node.
pub(crate) const INDEX_FANOUT: u64 = 512;
/// The deepest tree: 2^36 pages.
pub(crate) const INDEX_MAX_LEVELS: u8 = 4;
/// Pages the largest on-demand backing may hold.
pub(crate) const INDEX_MAX_PAGES: u64 = 1 << 36;
/// Frames one commit allocates at most: a node per level below the root,
/// and the page.
pub(crate) const INDEX_MAX_COMMIT_FRAMES: usize = INDEX_MAX_LEVELS as usize;

const PLACE_LEVEL_SHIFT: u32 = 60;
const _: () = assert!(INDEX_MAX_PAGES < 1 << PLACE_LEVEL_SHIFT);
const _: () = assert!(INDEX_FANOUT * 8 == BASE_PAGE_SIZE);

/// Reads, writes and zeroes index node pages and committed pages by
/// physical address: the direct map in the kernel, a model in host tests.
#[allow(
    unsafe_code,
    reason = "writing and zeroing physical pages is exclusive-ownership authority the caller attests"
)]
pub(crate) trait IndexMemory: Sync {
    /// Entry `entry` of the node page at physical `node`.
    fn read(&self, node: u64, entry: usize) -> u64;

    /// Writes entry `entry` of the node page at physical `node`.
    ///
    /// # Safety
    ///
    /// The caller must own the node page exclusively, as the role manager
    /// does for a page in an index role while it holds `&mut self`.
    unsafe fn write(&self, node: u64, entry: usize, value: u64);

    /// Zeroes the whole base page at physical `page`, with any cache
    /// maintenance it needs, or returns `false`.
    ///
    /// # Safety
    ///
    /// The caller must own the page exclusively and no mapping may name it.
    unsafe fn zero(&self, page: u64) -> bool;
}

/// The root of an on-demand backing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct IndexRootLink {
    /// The object's size in pages.
    pub(super) pages: u64,
    /// Levels of the tree, 1 to 4; the root's level is `levels - 1`.
    pub(super) levels: u8,
}

/// A node below the root, or a committed page: its root and its place. A
/// node's place is its first object page with its level in the top bits; a
/// page's is its object page.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct IndexEntryLink {
    pub(super) owner: u64,
    pub(super) place: u64,
}

const fn node_place(first_page: u64, level: u8) -> u64 {
    first_page | ((level as u64) << PLACE_LEVEL_SHIFT)
}

/// Pages one entry of a node at `level` covers.
const fn entry_span(level: u8) -> u64 {
    1 << (9 * level as u32)
}

/// The fewest levels that cover `pages`.
fn levels_for(pages: u64) -> Option<u8> {
    (1..=INDEX_MAX_LEVELS).find(|&levels| pages <= entry_span(levels))
}

/// What a commit made.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OnDemandCommit {
    /// The committed page.
    pub(crate) physical_start: u64,
    /// Frames this commit allocated, page and nodes: zero when the page
    /// was already committed.
    pub(crate) frames: u64,
}

/// One frame taken for a commit, not yet linked.
#[derive(Clone, Copy)]
struct Taken {
    slot: usize,
    identity: FrameRoleIdentity,
    range: PageRange,
}

/// A validated step of a walk from the root.
#[derive(Clone, Copy)]
struct IndexStep {
    /// The node holding the entry.
    node: u64,
    entry: usize,
    level: u8,
    /// The first object page the entry covers.
    first_page: u64,
}

/// The steps an index walk took, and the committed page it reached, if any.
type IndexWalk = (
    [Option<IndexStep>; INDEX_MAX_LEVELS as usize],
    Option<(FrameRoleIdentity, PageRange)>,
);
impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>
{
    /// Gives the manager its access to index pages. Until it has one, no
    /// on-demand backing can be made or read.
    pub(crate) fn set_index_memory(&mut self, memory: &'static dyn IndexMemory) {
        self.index_memory = Some(memory);
    }

    fn memory(&self) -> Result<&'static dyn IndexMemory, FrameRoleError> {
        self.index_memory.ok_or(FrameRoleError::WrongRole)
    }

    /// Makes an on-demand backing of `page_count` pages: one zeroed root
    /// node and no pages (DW2 M6 §8.3).
    pub(crate) fn allocate_on_demand_backing(
        &mut self,
        page_count: u64,
    ) -> Result<ObjectBackingGrant, FrameRoleError> {
        let levels = (page_count != 0)
            .then(|| levels_for(page_count))
            .flatten()
            .ok_or(FrameRoleError::Physical(
                PhysicalMemoryError::InvalidPageRange,
            ))?;
        let memory = self.memory()?;
        let root = self.take_index_frame(
            memory,
            FrameRole::IndexRoot(IndexRootLink {
                pages: page_count,
                levels,
            }),
        )?;
        Ok(ObjectBackingGrant {
            identity: BackingIdentity(root.identity),
            range: root.range,
            kind: ObjectBackingKind::OnDemand,
            pages: page_count,
            runs: 1,
        })
    }

    /// The root of the on-demand backing `head`.
    fn index_root(
        &self,
        head: FrameRoleIdentity,
    ) -> Result<(PageRange, IndexRootLink), FrameRoleError> {
        match self.index_root_at(self.slot(head)?) {
            Some(root) if head.domain == self.domain => Ok(root),
            Some(_) | None => Err(FrameRoleError::WrongRole),
        }
    }

    /// Checks that `[offset, offset + byte_len)` lies in `backing`, page
    /// aligned and nonempty, and that a writable use is allowed, without
    /// requiring an on-demand backing's pages to have frames (DW2 M6 §8.6).
    pub(crate) fn validate_object_range(
        &self,
        backing: BackingIdentity,
        offset: u64,
        byte_len: u64,
        writable: bool,
    ) -> Result<(), FrameRoleError> {
        let Ok((_, root)) = self.index_root(backing.0) else {
            return self
                .object_segments(backing, offset, byte_len, writable)
                .map(|_| ());
        };
        let pages = |bytes: u64| {
            bytes
                .is_multiple_of(BASE_PAGE_SIZE)
                .then_some(bytes / BASE_PAGE_SIZE)
        };
        let first = pages(offset).ok_or(FrameRoleError::WrongRole)?;
        let count = pages(byte_len)
            .filter(|count| *count != 0)
            .ok_or(FrameRoleError::WrongRole)?;
        match first.checked_add(count) {
            Some(end) if end <= root.pages => Ok(()),
            _ => Err(FrameRoleError::WrongRole),
        }
    }

    /// Whether `backing` is on demand.
    pub(crate) fn is_on_demand(&self, backing: BackingIdentity) -> bool {
        self.index_root(backing.0).is_ok()
    }

    /// The entry `raw` names, checked to hold `role` at `place` under the
    /// root `owner`.
    fn index_entry(
        &self,
        owner: FrameRoleIdentity,
        raw: u64,
        node: bool,
        place: u64,
    ) -> Result<(FrameRoleIdentity, PageRange, IndexEntryLink), FrameRoleError> {
        let identity = FrameRoleIdentity {
            domain: self.domain,
            raw,
        };
        let facts = self
            .index_entry_at(self.slot(identity)?)
            .filter(|facts| facts.node == node)
            .ok_or(FrameRoleError::WrongRole)?;
        let link = facts.link;
        if link.owner != owner.raw || link.place != place || facts.range.page_count() != 1 {
            return Err(FrameRoleError::WrongRole);
        }
        Ok((identity, facts.range, link))
    }

    /// Walks from the root of `head` towards `page`. Returns the steps taken
    /// down to the deepest node that exists, and the committed page if the
    /// walk reached it.
    fn index_walk(&self, head: FrameRoleIdentity, page: u64) -> Result<IndexWalk, FrameRoleError> {
        let (root_range, root) = self.index_root(head)?;
        if page >= root.pages {
            return Err(FrameRoleError::WrongRole);
        }
        let memory = self.memory()?;
        let mut steps = [None; INDEX_MAX_LEVELS as usize];
        let mut node = root_range.start;
        let mut node_first = 0_u64;
        for (depth, level) in (0..root.levels).rev().enumerate() {
            let span = entry_span(level);
            let entry = ((page - node_first) / span) as usize;
            let first_page = node_first + entry as u64 * span;
            steps[depth] = Some(IndexStep {
                node,
                entry,
                level,
                first_page,
            });
            let raw = memory.read(node, entry);
            if raw == 0 {
                return Ok((steps, None));
            }
            if level == 0 {
                let (identity, range, _) = self.index_entry(head, raw, false, page)?;
                return Ok((steps, Some((identity, range))));
            }
            let (_, range, _) =
                self.index_entry(head, raw, true, node_place(first_page, level - 1))?;
            node = range.start;
            node_first = first_page;
        }
        Err(FrameRoleError::InvariantViolation)
    }

    /// The committed page at object page `page` of the on-demand backing
    /// `head`, or [`FrameRoleError::Absent`] when it has none yet.
    pub(super) fn index_resolve(
        &self,
        head: FrameRoleIdentity,
        page: u64,
    ) -> Result<(FrameRoleIdentity, u64), FrameRoleError> {
        match self.index_walk(head, page)? {
            (_, Some((identity, range))) => Ok((identity, range.start)),
            (_, None) => Err(FrameRoleError::Absent),
        }
    }

    /// Frames committing `page` would allocate: zero when it is committed,
    /// else one per missing node and one for the page. A caller admits this
    /// many before [`Self::commit_on_demand_page`], in the same hold.
    pub(crate) fn on_demand_commit_cost(
        &self,
        backing: BackingIdentity,
        page: u64,
    ) -> Result<u64, FrameRoleError> {
        let (steps, found) = self.index_walk(backing.0, page)?;
        if found.is_some() {
            return Ok(0);
        }
        let deepest = steps
            .iter()
            .flatten()
            .last()
            .ok_or(FrameRoleError::InvariantViolation)?;
        Ok(u64::from(deepest.level) + 1)
    }

    /// Frames committing every page of `[first, first + count)` one after
    /// another would take: each absent page, and each node missing on their
    /// paths counted once, though several pages need it. A commit step
    /// admits this once instead of each page against the registry.
    pub(crate) fn on_demand_commit_range_cost(
        &self,
        backing: BackingIdentity,
        first: u64,
        count: u64,
    ) -> Result<u64, FrameRoleError> {
        let end = first
            .checked_add(count)
            .ok_or(FrameRoleError::InvariantViolation)?;
        // The node last counted at each height (1 = a leaf node): the pages
        // run in order, so a node a page shares is the one counted last.
        let mut counted: [Option<u64>; INDEX_MAX_COMMIT_FRAMES] = [None; INDEX_MAX_COMMIT_FRAMES];
        let mut total = 0_u64;
        for page in first..end {
            let (steps, found) = self.index_walk(backing.0, page)?;
            if found.is_some() {
                continue;
            }
            let deepest = steps
                .iter()
                .flatten()
                .last()
                .ok_or(FrameRoleError::InvariantViolation)?;
            total += 1;
            // The deepest existing node is at height `level + 1`; nodes of
            // heights 1..=level are missing.
            for height in 1..=u32::from(deepest.level) {
                let key = page >> (9 * height);
                let slot = &mut counted[height as usize];
                if *slot != Some(key) {
                    *slot = Some(key);
                    total += 1;
                }
            }
        }
        Ok(total)
    }

    /// Gives object page `page` of an on-demand backing a zeroed frame,
    /// with any nodes on its path. Either every frame is taken, zeroed and
    /// linked, or nothing changes. A page already committed is returned as
    /// it is.
    pub(crate) fn commit_on_demand_page(
        &mut self,
        backing: BackingIdentity,
        page: u64,
    ) -> Result<OnDemandCommit, FrameRoleError> {
        let head = backing.0;
        let (steps, found) = self.index_walk(head, page)?;
        if let Some((_, range)) = found {
            return Ok(OnDemandCommit {
                physical_start: range.start,
                frames: 0,
            });
        }
        let deepest = *steps
            .iter()
            .flatten()
            .last()
            .ok_or(FrameRoleError::InvariantViolation)?;
        let memory = self.memory()?;
        // Take the frames top-down: a node for each level below the deepest
        // existing one, then the page. On failure, give back what was taken.
        let mut taken: [Option<Taken>; INDEX_MAX_COMMIT_FRAMES] = [None; INDEX_MAX_COMMIT_FRAMES];
        let mut first_page = deepest.first_page;
        for (index, level) in (0..=deepest.level).rev().enumerate() {
            let role = if level == 0 {
                FrameRole::ObjectPage(IndexEntryLink {
                    owner: head.raw,
                    place: page,
                })
            } else {
                FrameRole::IndexNode(IndexEntryLink {
                    owner: head.raw,
                    place: node_place(first_page, level - 1),
                })
            };
            match self.take_index_frame(memory, role) {
                Ok(frame) => taken[index] = Some(frame),
                Err(error) => {
                    for frame in taken.iter().flatten() {
                        self.untake_index_frame(*frame);
                    }
                    return Err(error);
                }
            }
            if level != 0 {
                let span = entry_span(level - 1);
                first_page += (page - first_page) / span * span;
            }
        }
        // Link them: each into its parent, the first into the deepest
        // existing node. Every frame is zeroed, so a new node is empty.
        let mut parent = (deepest.node, deepest.entry);
        let mut level = deepest.level;
        let mut node_first = deepest.first_page;
        let mut frames = 0_u64;
        let mut physical_start = 0;
        for frame in taken.iter().flatten() {
            #[allow(
                unsafe_code,
                reason = "the manager owns its index nodes exclusively under `&mut self`"
            )]
            // SAFETY: `parent` is a node of this backing, which the manager
            // owns exclusively under `&mut self`.
            unsafe {
                memory.write(parent.0, parent.1, frame.identity.raw)
            };
            frames += 1;
            physical_start = frame.range.start;
            if level != 0 {
                let span = entry_span(level - 1);
                let entry = ((page - node_first) / span) as usize;
                parent = (frame.range.start, entry);
                node_first += entry as u64 * span;
                level -= 1;
            }
        }
        Ok(OnDemandCommit {
            physical_start,
            frames,
        })
    }

    /// Takes one zeroed page and publishes `role` on it.
    fn take_index_frame(
        &mut self,
        memory: &'static dyn IndexMemory,
        role: FrameRole,
    ) -> Result<Taken, FrameRoleError> {
        let (slot, generation, identity, range) = self.take_run(1)?;
        #[allow(
            unsafe_code,
            reason = "a run just taken from the free list is owned by nothing else"
        )]
        // SAFETY: the run was just taken from the free list; nothing else
        // owns or maps it.
        if !unsafe { memory.zero(range.start) } {
            self.allocator
                .free_run(range)
                .expect("a run just taken frees");
            return Err(FrameRoleError::InitializationFailed);
        }
        self.occupy(slot, generation, RoleRecord { range, role });
        Ok(Taken {
            slot,
            identity,
            range,
        })
    }

    /// Gives back a frame [`Self::take_index_frame`] took, before any entry
    /// names it.
    fn untake_index_frame(&mut self, frame: Taken) {
        self.allocator
            .free_run(frame.range)
            .expect("a live run frees: the boot free list is sized by the role slots (M1), and the buddy allocator links every page");
        self.vacate(frame.slot);
    }

    /// Counts every node and committed page below the root of `head`,
    /// checking each.
    fn index_count(&self, head: FrameRoleIdentity) -> Result<u64, FrameRoleError> {
        let (root_range, root) = self.index_root(head)?;
        let memory = self.memory()?;
        self.index_count_node(
            memory,
            head,
            root_range.start,
            root.levels - 1,
            0,
            root.pages,
        )
    }

    fn index_count_node(
        &self,
        memory: &'static dyn IndexMemory,
        head: FrameRoleIdentity,
        node: u64,
        level: u8,
        first_page: u64,
        pages: u64,
    ) -> Result<u64, FrameRoleError> {
        let span = entry_span(level);
        let mut frames = 0_u64;
        for entry in 0..INDEX_FANOUT as usize {
            let raw = memory.read(node, entry);
            if raw == 0 {
                continue;
            }
            let entry_first = first_page + entry as u64 * span;
            if entry_first >= pages {
                return Err(FrameRoleError::WrongRole);
            }
            if level == 0 {
                self.index_entry(head, raw, false, entry_first)?;
            } else {
                let (_, range, _) =
                    self.index_entry(head, raw, true, node_place(entry_first, level - 1))?;
                frames += self.index_count_node(
                    memory,
                    head,
                    range.start,
                    level - 1,
                    entry_first,
                    pages,
                )?;
            }
            frames += 1;
        }
        Ok(frames)
    }

    /// The frames an on-demand backing holds: its root, nodes and committed
    /// pages, the weight its object is charged (DW2 M6 §8.4).
    pub(crate) fn on_demand_frames(&self, backing: BackingIdentity) -> Result<u64, FrameRoleError> {
        Ok(self.index_count(backing.0)? + 1)
    }

    /// Frees the committed pages of the on-demand backing in object pages
    /// `[start, end)` (clamped to the object), visiting at most `budget`
    /// index entries: a committed page, or an absent entry, whose whole span
    /// is skipped at once. Nodes stay. Returns the first page not examined,
    /// the pages freed and the entries visited (DW2 §10.9 item 5).
    ///
    /// The caller guarantees no mapping, TLB, device or kernel access can
    /// still reach a page of the range.
    pub(crate) fn decommit_on_demand_range(
        &mut self,
        backing: BackingIdentity,
        start: u64,
        end: u64,
        budget: u64,
    ) -> Result<(u64, u64, u64), FrameRoleError> {
        let head = backing.0;
        let (_, root) = self.index_root(head)?;
        let end = end.min(root.pages);
        let memory = self.memory()?;
        let mut cursor = start;
        let mut freed = 0_u64;
        let mut visited = 0_u64;
        while cursor < end && visited < budget {
            let (steps, found) = self.index_walk(head, cursor)?;
            let deepest = *steps
                .iter()
                .flatten()
                .last()
                .ok_or(FrameRoleError::InvariantViolation)?;
            visited += 1;
            match found {
                Some((identity, _)) => {
                    #[allow(
                        unsafe_code,
                        reason = "the manager owns its index nodes exclusively under `&mut self`"
                    )]
                    // SAFETY: `deepest.node` is a node of this backing, which
                    // the manager owns exclusively under `&mut self`.
                    unsafe {
                        memory.write(deepest.node, deepest.entry, 0)
                    };
                    let slot = self.slot(identity)?;
                    self.free_index_slot(slot);
                    freed += 1;
                    cursor += 1;
                }
                None => {
                    cursor = deepest
                        .first_page
                        .checked_add(entry_span(deepest.level))
                        .ok_or(FrameRoleError::InvariantViolation)?;
                }
            }
        }
        Ok((cursor.min(end.max(start)), freed, visited))
    }

    /// One step of finalizing an on-demand backing (DW2 §10.12 item 2):
    /// frees its committed pages and nodes in object-page order from
    /// `cursor`, visiting at most `budget` entries. A committed page is
    /// unlinked and freed; an absent entry skips its span; once the cursor
    /// reaches the end of a node below the root (its span, clamped to the
    /// object), that node is empty and is freed with its parent entry
    /// cleared, cascading upward before the budget is checked again, so a
    /// step may visit up to `INDEX_MAX_LEVELS - 1` entries past `budget`.
    /// The root stays. Returns the new cursor, the frames freed and the
    /// entries visited; the index below the root is empty once the cursor
    /// reaches the object's end.
    ///
    /// The caller guarantees nothing can commit into the backing or reach
    /// its pages: its object is finalizing.
    pub(crate) fn release_index_step(
        &mut self,
        backing: BackingIdentity,
        cursor: u64,
        budget: u64,
    ) -> Result<(u64, u64, u64), FrameRoleError> {
        let head = backing.0;
        let (_, root) = self.index_root(head)?;
        let pages = root.pages;
        let memory = self.memory()?;
        let mut cursor = cursor.min(pages);
        let mut freed = 0_u64;
        let mut visited = 0_u64;
        while cursor < pages && visited < budget {
            let (steps, found) = self.index_walk(head, cursor)?;
            let depth = steps
                .iter()
                .rposition(Option::is_some)
                .ok_or(FrameRoleError::InvariantViolation)?;
            let deepest = steps[depth].ok_or(FrameRoleError::InvariantViolation)?;
            visited += 1;
            match found {
                Some((identity, _)) => {
                    #[allow(
                        unsafe_code,
                        reason = "the manager owns its index nodes exclusively under `&mut self`"
                    )]
                    // SAFETY: `deepest.node` is a node of this backing, which
                    // the manager owns exclusively under `&mut self`.
                    unsafe {
                        memory.write(deepest.node, deepest.entry, 0)
                    };
                    let slot = self.slot(identity)?;
                    self.free_index_slot(slot);
                    freed += 1;
                    cursor += 1;
                }
                None => {
                    cursor = deepest
                        .first_page
                        .checked_add(entry_span(deepest.level))
                        .ok_or(FrameRoleError::InvariantViolation)?
                        .min(pages);
                }
            }
            // The node at each depth below the root is the child its parent
            // step's entry names; it ends where that entry's span ends.
            for level in (1..=depth).rev() {
                let parent = steps[level - 1].ok_or(FrameRoleError::InvariantViolation)?;
                let end = parent
                    .first_page
                    .checked_add(entry_span(parent.level))
                    .ok_or(FrameRoleError::InvariantViolation)?
                    .min(pages);
                if cursor < end {
                    break;
                }
                let raw = memory.read(parent.node, parent.entry);
                let (identity, _, _) = self.index_entry(
                    head,
                    raw,
                    true,
                    node_place(parent.first_page, parent.level - 1),
                )?;
                #[allow(
                    unsafe_code,
                    reason = "the manager owns its index nodes exclusively under `&mut self`"
                )]
                // SAFETY: `parent.node` is a node of this backing, which the
                // manager owns exclusively under `&mut self`.
                unsafe {
                    memory.write(parent.node, parent.entry, 0)
                };
                let slot = self.slot(identity)?;
                self.free_index_slot(slot);
                freed += 1;
                visited += 1;
            }
        }
        Ok((cursor, freed, visited))
    }

    /// Frees an on-demand backing whole, after checking every node and
    /// page.
    pub(super) fn release_index(&mut self, head: FrameRoleIdentity) -> Result<(), FrameRoleError> {
        self.index_count(head)?;
        let (root_range, root) = self.index_root(head)?;
        let memory = self.memory()?;
        self.index_free_node(memory, head, root_range.start, root.levels - 1, 0);
        let root_slot = self.slot(head)?;
        self.free_index_slot(root_slot);
        Ok(())
    }

    /// Frees every frame below the checked node at `node`, children first.
    fn index_free_node(
        &mut self,
        memory: &'static dyn IndexMemory,
        head: FrameRoleIdentity,
        node: u64,
        level: u8,
        first_page: u64,
    ) {
        let span = entry_span(level);
        for entry in 0..INDEX_FANOUT as usize {
            let raw = memory.read(node, entry);
            if raw == 0 {
                continue;
            }
            let entry_first = first_page + entry as u64 * span;
            let place = if level == 0 {
                entry_first
            } else {
                node_place(entry_first, level - 1)
            };
            let (identity, range, _) = self
                .index_entry(head, raw, level != 0, place)
                .expect("a checked index stays whole while it is freed");
            if level != 0 {
                self.index_free_node(memory, head, range.start, level - 1, entry_first);
            }
            let slot = self.slot(identity).expect("a checked entry is live");
            self.free_index_slot(slot);
        }
    }

    fn free_index_slot(&mut self, slot: usize) {
        let range = self.run_at(slot).expect("a freed index frame is live");
        self.allocator
            .free_run(range)
            .expect("a live run frees: the boot free list is sized by the role slots (M1), and the buddy allocator links every page");
        self.vacate(slot);
    }

    /// Every index node and committed page is reached from exactly one
    /// root's walk.
    pub(super) fn check_indexes(&self) -> Result<(), FrameRoleError> {
        let mut linked = 0_u64;
        let mut reached = 0_u64;
        for (slot, entry) in self.slot_views() {
            let Some(record) = entry.record else {
                continue;
            };
            match record.role {
                FrameRole::IndexNode(_) | FrameRole::ObjectPage(_) => linked += 1,
                FrameRole::IndexRoot(_) => {
                    let identity = self.identity(slot, entry.generation)?;
                    reached += self
                        .index_count(identity)
                        .map_err(|_| FrameRoleError::InvariantViolation)?;
                }
                FrameRole::AllocatedUninitialized
                | FrameRole::Zeroed
                | FrameRole::BackingAllocated(_)
                | FrameRole::ObjectBacking(_)
                | FrameRole::ArchitectureBootstrap(_)
                | FrameRole::TableCandidate { .. }
                | FrameRole::PageTable { .. }
                | FrameRole::External(_)
                | FrameRole::ExternalImmutableModule { .. }
                | FrameRole::ExternalDeviceMmio
                | FrameRole::RoleTableStorage => {}
            }
        }
        if linked != reached {
            return Err(FrameRoleError::InvariantViolation);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "index_tests.rs"]
mod tests;

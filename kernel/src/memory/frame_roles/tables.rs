//! Page-table roles: owners, candidates, commits and the empty-hierarchy
//! proofs that let a retired address space's tables be freed.

use super::*;

impl<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>
    FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>
{
    pub(crate) fn create_table_owner(&mut self) -> Result<TableOwnerKey, FrameRoleError> {
        let raw = self.next_table_owner;
        self.next_table_owner = raw
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(FrameRoleError::InvalidTableOwner)?;
        Ok(TableOwnerKey {
            domain: self.domain,
            raw,
        })
    }

    pub(crate) fn prepare_table(
        &mut self,
        grant: ZeroedGrant,
        owner: TableOwnerKey,
        level: TableLevel,
    ) -> Result<TableCandidateGrant, GrantTransitionError<ZeroedGrant>> {
        if let Err(error) = self.validate_owner(owner) {
            return Err(GrantTransitionError::new(error, grant));
        }
        if grant.range.page_count() != 1 {
            return Err(GrantTransitionError::new(FrameRoleError::WrongRole, grant));
        }
        if let Err(error) = self.transition(
            grant.identity,
            grant.range,
            FrameRole::Zeroed,
            FrameRole::TableCandidate { owner, level },
        ) {
            return Err(GrantTransitionError::new(error, grant));
        }
        Ok(TableCandidateGrant {
            identity: grant.identity,
            range: grant.range,
            owner,
            level,
        })
    }

    pub(crate) fn commit_table(
        &mut self,
        grant: TableCandidateGrant,
        parent: Option<TableIdentity>,
    ) -> Result<TableIdentity, GrantTransitionError<TableCandidateGrant>> {
        let parent = parent.map(TableCommitParent::Committed);
        let staged = self.stage_table_commit(grant, parent)?;
        Ok(self.publish_staged_table(staged))
    }

    pub(crate) fn stage_table_commit(
        &self,
        grant: TableCandidateGrant,
        parent: Option<TableCommitParent<'_>>,
    ) -> Result<StagedTableCommit, GrantTransitionError<TableCandidateGrant>> {
        if let Err(error) = self.validate_owner(grant.owner) {
            return Err(GrantTransitionError::new(error, grant));
        }
        let slot = match self.slot(grant.identity) {
            Ok(slot) => slot,
            Err(error) => return Err(GrantTransitionError::new(error, grant)),
        };
        if self.record_at(slot)
            != Some(RoleRecord {
                range: grant.range,
                role: FrameRole::TableCandidate {
                    owner: grant.owner,
                    level: grant.level,
                },
            })
        {
            return Err(GrantTransitionError::new(FrameRoleError::WrongRole, grant));
        }
        if grant.level == TableLevel::Pml4 && self.has_other_root(grant.owner, slot) {
            return Err(GrantTransitionError::new(
                FrameRoleError::DuplicateTableRoot,
                grant,
            ));
        }
        let parent_role = match (grant.level, parent) {
            (TableLevel::Pml4, None) => None,
            (TableLevel::Pml4, Some(_)) | (_, None) => {
                return Err(GrantTransitionError::new(
                    FrameRoleError::InvalidTableParent,
                    grant,
                ));
            }
            (level, Some(TableCommitParent::Committed(parent))) => {
                if self.validate_table_identity(parent).is_err()
                    || parent.owner != grant.owner
                    || parent.level.child() != Some(level)
                {
                    return Err(GrantTransitionError::new(
                        FrameRoleError::InvalidTableParent,
                        grant,
                    ));
                }
                Some(parent.role)
            }
            (level, Some(TableCommitParent::Candidate(parent))) => {
                let record = match self.record(parent.identity) {
                    Ok(record) => record,
                    Err(_) => {
                        return Err(GrantTransitionError::new(
                            FrameRoleError::InvalidTableParent,
                            grant,
                        ));
                    }
                };
                if record.range != parent.range
                    || record.role
                        != (FrameRole::TableCandidate {
                            owner: parent.owner,
                            level: parent.level,
                        })
                    || parent.owner != grant.owner
                    || parent.level.child() != Some(level)
                {
                    return Err(GrantTransitionError::new(
                        FrameRoleError::InvalidTableParent,
                        grant,
                    ));
                }
                Some(parent.identity)
            }
        };
        Ok(StagedTableCommit {
            grant,
            slot,
            parent: parent_role,
        })
    }

    pub(crate) fn publish_staged_table(&mut self, staged: StagedTableCommit) -> TableIdentity {
        assert_eq!(
            self.validate_staged_table(&staged),
            Ok(()),
            "staged table commit became invalid before publication"
        );
        let grant = staged.grant;
        // Every committed table below a root counts toward that root, which
        // is how an empty-hierarchy proof knows it saw them all.
        // Every table below a PML4 also counts toward its parent, unless the
        // parent is that PML4, so a table freed alone can prove it has no
        // committed child left (DW2 §10.14 revision 2 item 2).
        if let Some(parent) = staged.parent {
            let root = self
                .root_slot_of(parent)
                .expect("a validated parent table leads to its root");
            let parent = self
                .slot(parent)
                .expect("a validated parent table has a live slot");
            for counted in [Some(root), (parent != root).then_some(parent)]
                .into_iter()
                .flatten()
            {
                let tables = self
                    .table_at(counted)
                    .expect("a counted slot is a committed table")
                    .tables
                    .checked_add(1)
                    .expect("a table count stays below the slot count");
                self.set_tables(counted, tables);
            }
        }
        self.replace_record(
            staged.slot,
            RoleRecord {
                range: grant.range,
                role: FrameRole::PageTable {
                    owner: grant.owner,
                    level: grant.level,
                    parent: staged.parent,
                },
            },
        );
        TableIdentity {
            role: grant.identity,
            owner: grant.owner,
            level: grant.level,
            physical_start: grant.range.start,
        }
    }

    pub(crate) fn cancel_staged_table(
        &mut self,
        staged: StagedTableCommit,
    ) -> Result<(), GrantTransitionError<TableCandidateGrant>> {
        self.cancel_table_candidate(staged.grant)
    }

    pub(crate) fn validate_table_identity(
        &self,
        table: TableIdentity,
    ) -> Result<(), FrameRoleError> {
        let facts = self.table_facts(table.role)?;
        if facts.start != table.physical_start
            || table.owner.domain != self.domain
            || facts.owner != table.owner.raw
            || facts.level != table.level
        {
            return Err(FrameRoleError::WrongRole);
        }
        Ok(())
    }

    pub(crate) fn table_identity(
        &self,
        owner: TableOwnerKey,
        level: TableLevel,
        physical_start: u64,
    ) -> Result<TableIdentity, FrameRoleError> {
        self.validate_owner(owner)?;
        // Page tables are dynamic roles, so the start index finds them.
        let slot = self
            .dynamic_slot_at(physical_start)
            .ok_or(FrameRoleError::WrongRole)?;
        // `validate_owner` guarantees the owner's domain is this manager's.
        let facts = self.table_at(slot).ok_or(FrameRoleError::WrongRole)?;
        if !(facts.start == physical_start && facts.owner == owner.raw && facts.level == level) {
            return Err(FrameRoleError::WrongRole);
        }
        let generation = self
            .live_generation(slot)
            .ok_or(FrameRoleError::WrongRole)?;
        Ok(TableIdentity {
            role: self.identity(slot, generation)?,
            owner,
            level,
            physical_start,
        })
    }

    pub(crate) fn validate_table_child(
        &self,
        parent: TableIdentity,
        child: TableIdentity,
    ) -> Result<(), FrameRoleError> {
        self.validate_table_identity(parent)?;
        self.validate_table_identity(child)?;
        if parent.owner != child.owner || parent.level.child() != Some(child.level) {
            return Err(FrameRoleError::InvalidTableParent);
        }
        // Both identities were validated by `slot`, so their domain is this
        // manager's and the raw parent compares.
        if self.table_facts(child.role)?.parent != parent.role.raw {
            return Err(FrameRoleError::InvalidTableParent);
        }
        Ok(())
    }

    /// Starts an architecture-attested empty-hierarchy preflight for one exact
    /// committed PML4. Descendants must subsequently be observed top-down.
    pub(crate) fn begin_empty_table_hierarchy(
        &mut self,
        root: TableIdentity,
    ) -> Result<EmptyTableHierarchyCandidate, FrameRoleError> {
        self.validate_table_identity(root)?;
        if root.level != TableLevel::Pml4 {
            return Err(FrameRoleError::WrongRole);
        }
        let epoch = self.next_epoch;
        self.next_epoch = epoch
            .checked_add(1)
            .ok_or(FrameRoleError::InvariantViolation)?;
        let slot = self.slot(root.role)?;
        self.set_mark(slot, epoch);
        Ok(EmptyTableHierarchyCandidate {
            root,
            epoch,
            version: self.version,
            observed: 0,
        })
    }

    /// Records one exact child discovered by the architecture walk. Requiring
    /// the parent to have already been observed makes the proof structurally
    /// top-down; rejecting a slot observed twice catches same-frame aliases.
    pub(crate) fn observe_empty_table_child(
        &mut self,
        candidate: &mut EmptyTableHierarchyCandidate,
        parent: TableIdentity,
        child: TableIdentity,
    ) -> Result<(), FrameRoleError> {
        if candidate.version != self.version {
            return Err(FrameRoleError::InvalidTableParent);
        }
        self.validate_table_identity(candidate.root)?;
        if candidate.root.owner != parent.owner || candidate.root.owner != child.owner {
            return Err(FrameRoleError::InvalidTableParent);
        }
        let parent_slot = self.slot(parent.role)?;
        if self.table_at(parent_slot).map(|facts| facts.mark) != Some(candidate.epoch) {
            return Err(FrameRoleError::InvalidTableParent);
        }
        self.validate_table_child(parent, child)?;
        let child_slot = self.slot(child.role)?;
        if self.table_at(child_slot).map(|facts| facts.mark) == Some(candidate.epoch) {
            return Err(FrameRoleError::InvalidTableParent);
        }
        self.set_mark(child_slot, candidate.epoch);
        candidate.observed = candidate
            .observed
            .checked_add(1)
            .ok_or(FrameRoleError::InvalidTableParent)?;
        Ok(())
    }

    /// Seals the hierarchy proof only when the architecture walk accounted for
    /// every committed table below the root. Each observed table was a
    /// distinct committed table of the root's owner below it, and none changed
    /// since (the role version), so when their number equals the root's count
    /// they are exactly that set: no disconnected table record is left over.
    pub(crate) fn finish_empty_table_hierarchy(
        &self,
        candidate: EmptyTableHierarchyCandidate,
    ) -> Result<EmptyTableHierarchyGrant, FrameRoleError> {
        if candidate.version != self.version {
            return Err(FrameRoleError::InvalidTableParent);
        }
        self.validate_table_identity(candidate.root)?;
        let root = self.table_facts(candidate.root.role)?;
        if root.mark != candidate.epoch || root.tables != candidate.observed {
            return Err(FrameRoleError::InvalidTableParent);
        }
        Ok(EmptyTableHierarchyGrant {
            root: candidate.root,
            epoch: candidate.epoch,
            version: candidate.version,
            remaining: candidate.observed,
        })
    }

    /// Reclaims one table the proof observed, after the architecture root has
    /// atomically disconnected its low half. Architecture teardown walks the
    /// disconnected hierarchy again and reclaims each table after its
    /// children; any order would do, since nothing can reach them.
    ///
    /// # Safety
    ///
    /// The caller must own the architecture binding for `grant`, must have
    /// closed its residency gate with zero resident CPUs, must have atomically
    /// cleared every observed low-half PML4 entry, and must retain exclusive
    /// access to this manager through root reclaim.
    #[allow(
        unsafe_code,
        reason = "architecture residency and atomic root disconnection are outside the target-independent role manager"
    )]
    pub(crate) unsafe fn reclaim_preflighted_table(
        &mut self,
        grant: &mut EmptyTableHierarchyGrant,
        table: TableIdentity,
    ) {
        assert_eq!(
            grant.version, self.version,
            "a role changed during preflighted hierarchy reclaim"
        );
        let slot = self
            .slot(table.role)
            .unwrap_or_else(|error| panic!("preflighted table disappeared: {error:?}"));
        let Some(facts) = self
            .table_at(slot)
            .filter(|facts| facts.level != TableLevel::Pml4)
        else {
            panic!("preflighted table is not a committed child table");
        };
        // The grant's root and the table's identity were minted by this
        // manager (`slot` checked the table's), so owners compare raw.
        if facts.mark != grant.epoch
            || grant.root.owner.domain != self.domain
            || facts.owner != grant.root.owner.raw
            || facts.level != table.level
            || facts.start != table.physical_start
        {
            panic!("table was not observed by this hierarchy proof");
        }
        let owner = grant.root.owner;
        let level = facts.level;
        let parent = FrameRoleIdentity {
            domain: self.domain,
            raw: facts.parent,
        };
        let range = PageRange {
            start: facts.start,
            end: facts.start + BASE_PAGE_SIZE,
        };
        grant.remaining = grant
            .remaining
            .checked_sub(1)
            .expect("a proof reclaims no more tables than it observed");
        let root = self
            .slot(grant.root.role)
            .expect("the hierarchy root outlives its tables");
        // The proof's tables go in any order, so a parent may be gone
        // already, its count with it.
        let parent_slot = self.slot(parent).ok();
        self.uncount_table(root, parent_slot);
        self.cancel(
            table.role,
            range,
            FrameRole::PageTable {
                owner,
                level,
                parent: Some(parent),
            },
        )
        .unwrap_or_else(|error| panic!("preflighted table reclaim drifted: {error:?}"));
        grant.version = self.version;
    }

    /// Lowers the counts a child table added when it was committed: its
    /// root's (slot `root`), and its parent's (slot `parent`, when given)
    /// unless that is the root.
    fn uncount_table(&mut self, root: usize, parent: Option<usize>) {
        for counted in [Some(root), parent.filter(|parent| *parent != root)]
            .into_iter()
            .flatten()
        {
            let tables = self
                .table_at(counted)
                .expect("a counted slot is a committed table")
                .tables
                .checked_sub(1)
                .expect("a table count covers every committed child it counted");
            self.set_tables(counted, tables);
        }
    }

    /// How many committed tables below the PML4 `root` its owner has.
    pub(crate) fn hierarchy_table_count(&self, root: TableIdentity) -> Result<u32, FrameRoleError> {
        self.validate_table_identity(root)?;
        if root.level != TableLevel::Pml4 {
            return Err(FrameRoleError::WrongRole);
        }
        Ok(self.table_facts(root.role)?.tables)
    }

    /// Checks that `table` may be freed alone from the retiring hierarchy
    /// of the PML4 `root` (DW2 §10.14 revision 2 item 2): a committed child
    /// table (never the PML4) of `root`'s owner, of the level below
    /// `parent`, whose recorded parent is `parent`, which itself lies
    /// below `root`; and no committed table names it as parent. Changes
    /// nothing.
    pub(crate) fn check_retiring_table(
        &self,
        root: TableIdentity,
        parent: TableIdentity,
        table: TableIdentity,
    ) -> Result<(), FrameRoleError> {
        self.validate_table_identity(root)?;
        if root.level != TableLevel::Pml4 || table.level == TableLevel::Pml4 {
            return Err(FrameRoleError::WrongRole);
        }
        if parent.owner != root.owner || table.owner != root.owner {
            return Err(FrameRoleError::InvalidTableOwner);
        }
        self.validate_table_child(parent, table)?;
        if self.root_slot_of(parent.role)? != self.slot(root.role)? {
            return Err(FrameRoleError::InvalidTableParent);
        }
        if self.table_facts(table.role)?.tables != 0 {
            return Err(FrameRoleError::InvalidTableParent);
        }
        Ok(())
    }

    /// Frees one user table of a retiring hierarchy, bottom-up, without
    /// reading it (DW2 §10.14 revision 2 item 2), after
    /// [`Self::check_retiring_table`]'s checks, which it repeats: on a
    /// refusal nothing changes. It lowers the root's count of tables and
    /// `parent`'s count of children. Charges are untouched.
    ///
    /// # Safety
    ///
    /// The caller must own the architecture binding of `root`, which must be
    /// retiring: its residency gate closed for good with no CPU resident,
    /// so no CPU can walk it or hold a translation or paging-structure entry
    /// cached from it (no PCID, no global user pages). Before any later walk
    /// of `parent`, the caller must clear `parent`'s entry naming `table`.
    #[allow(
        unsafe_code,
        reason = "root retirement and residency are architecture facts the target-independent role manager cannot see"
    )]
    pub(crate) unsafe fn reclaim_retiring_table(
        &mut self,
        root: TableIdentity,
        parent: TableIdentity,
        table: TableIdentity,
    ) -> Result<(), FrameRoleError> {
        self.check_retiring_table(root, parent, table)?;
        let parent_role = parent.role;
        let root = self.slot(root.role)?;
        let parent = self.slot(parent.role)?;
        self.uncount_table(root, Some(parent));
        let range = self.record(table.role)?.range;
        self.cancel(
            table.role,
            range,
            FrameRole::PageTable {
                owner: table.owner,
                level: table.level,
                parent: Some(parent_role),
            },
        )
        .unwrap_or_else(|error| panic!("a checked retiring table's reclaim drifted: {error:?}"));
        Ok(())
    }

    /// Ends hierarchy reclaim once every observed table is reclaimed. The
    /// returned root grant remains gated by the retired/nonresident root
    /// reclaim API.
    pub(crate) fn finish_preflighted_hierarchy(
        &self,
        grant: EmptyTableHierarchyGrant,
    ) -> EmptyTableRootGrant {
        assert_eq!(
            (grant.remaining, grant.version),
            (0, self.version),
            "preflighted hierarchy reclaim left tables or saw a role change"
        );
        self.prepare_empty_table_root(grant.root)
            .unwrap_or_else(|error| {
                panic!("retired hierarchy root did not become empty: {error:?}")
            })
    }

    /// The slot of the PML4 above committed table `identity` (or its own).
    fn root_slot_of(&self, mut identity: FrameRoleIdentity) -> Result<usize, FrameRoleError> {
        for _ in 0..4 {
            let slot = self.slot(identity)?;
            match self.table_at(slot) {
                Some(TableFacts {
                    level: TableLevel::Pml4,
                    ..
                }) => return Ok(slot),
                Some(facts) => {
                    identity = FrameRoleIdentity {
                        domain: self.domain,
                        raw: facts.parent,
                    };
                }
                None => return Err(FrameRoleError::InvalidTableParent),
            }
        }
        Err(FrameRoleError::InvalidTableParent)
    }

    /// Reclaims one dynamically allocated, committed PML4 only after its
    /// address-space owner has proved teardown complete and no committed child
    /// table remains attached. Shared kernel-half descendants are deliberately
    /// not represented as children of this owner; their lifetime remains with
    /// the primordial kernel-half binding.
    pub(crate) fn prepare_empty_table_root(
        &self,
        root: TableIdentity,
    ) -> Result<EmptyTableRootGrant, FrameRoleError> {
        self.validate_empty_table_root(root)?;
        Ok(EmptyTableRootGrant { root })
    }

    fn validate_empty_table_root(&self, root: TableIdentity) -> Result<(), FrameRoleError> {
        self.validate_table_identity(root)?;
        if root.level != TableLevel::Pml4 {
            return Err(FrameRoleError::WrongRole);
        }
        if self.table_facts(root.role)?.tables != 0 {
            return Err(FrameRoleError::InvalidTableParent);
        }
        Ok(())
    }

    /// The facts of the committed table `identity` names: `WrongRole` if
    /// it names a live slot that is not one.
    fn table_facts(&self, identity: FrameRoleIdentity) -> Result<TableFacts, FrameRoleError> {
        self.table_at(self.slot(identity)?)
            .ok_or(FrameRoleError::WrongRole)
    }

    fn validate_owner(&self, owner: TableOwnerKey) -> Result<(), FrameRoleError> {
        if owner.domain != self.domain || owner.raw == 0 || owner.raw >= self.next_table_owner {
            return Err(FrameRoleError::InvalidTableOwner);
        }
        Ok(())
    }

    fn validate_staged_table(&self, staged: &StagedTableCommit) -> Result<(), FrameRoleError> {
        let grant = &staged.grant;
        self.validate_owner(grant.owner)?;
        if self.slot(grant.identity)? != staged.slot
            || self.record_at(staged.slot)
                != Some(RoleRecord {
                    range: grant.range,
                    role: FrameRole::TableCandidate {
                        owner: grant.owner,
                        level: grant.level,
                    },
                })
        {
            return Err(FrameRoleError::InvalidGrant);
        }

        match (grant.level, staged.parent) {
            (TableLevel::Pml4, None) => {
                // The root list holds every slot of PML4 level (DW2 §12.3).
                if self.has_other_root(grant.owner, staged.slot) {
                    return Err(FrameRoleError::DuplicateTableRoot);
                }
            }
            (TableLevel::Pml4, Some(_)) | (_, None) => {
                return Err(FrameRoleError::InvalidTableParent);
            }
            (level, Some(parent)) => {
                if parent == grant.identity {
                    return Err(FrameRoleError::InvalidTableParent);
                }
                let parent = self.record(parent)?;
                let valid_parent = match parent.role {
                    FrameRole::PageTable {
                        owner,
                        level: parent_level,
                        ..
                    } => owner == grant.owner && parent_level.child() == Some(level),
                    _ => false,
                };
                if !valid_parent {
                    return Err(FrameRoleError::InvalidTableParent);
                }
            }
        }
        Ok(())
    }
}

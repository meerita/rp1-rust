//! Multiplexed request identity for one connection.
//!
//! The allocator hands out monotonic initiator identifiers starting at 1
//! and skipping the reserved 0 on wrap. The registry holds the live set:
//! an identifier is live from admission until its terminal frame retires
//! it, and it is released exactly once. A retired identifier may be
//! reused; a live one may not.

use std::collections::HashSet;

/// Allocates monotonic initiator request identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestIdAllocator {
    next: u64,
}

impl RequestIdAllocator {
    /// Builds an allocator starting at 1.
    pub const fn new() -> Self {
        Self { next: 1 }
    }

    /// Builds an allocator starting at `next`, for boundary tests.
    ///
    /// A start of 0 is treated as 1 on the next allocation because 0 names
    /// no request.
    #[cfg(test)]
    pub const fn with_start(next: u64) -> Self {
        Self { next }
    }

    /// Returns the next identifier, skipping the reserved 0.
    pub const fn allocate(&mut self) -> u64 {
        if self.next == 0 {
            self.next = 1;
        }
        let id = self.next;
        let advanced = self.next.wrapping_add(1);
        self.next = if advanced == 0 { 1 } else { advanced };
        id
    }
}

/// A refusal to admit an identifier into the live set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    /// The identifier is the reserved 0.
    Reserved,
    /// The identifier is already live.
    LiveReuse,
}

/// Tracks the identifiers in flight on one connection.
#[derive(Debug, Clone, Default)]
pub struct InFlightRegistry {
    live: HashSet<u64>,
}

impl InFlightRegistry {
    /// Builds an empty registry.
    pub fn new() -> Self {
        Self {
            live: HashSet::new(),
        }
    }

    /// Admits `id` into the live set.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::Reserved`] for 0 and
    /// [`RegistryError::LiveReuse`] when `id` is already live.
    pub fn insert(&mut self, id: u64) -> Result<(), RegistryError> {
        if id == 0 {
            return Err(RegistryError::Reserved);
        }
        if self.live.contains(&id) {
            return Err(RegistryError::LiveReuse);
        }
        let _ = self.live.insert(id);
        Ok(())
    }

    /// Retires `id`, returning whether it was live.
    ///
    /// Each live identifier is retired exactly once; a second retire
    /// reports `false` and changes nothing.
    pub fn retire(&mut self, id: u64) -> bool {
        self.live.remove(&id)
    }

    /// Returns whether `id` is live.
    pub fn contains(&self, id: u64) -> bool {
        self.live.contains(&id)
    }

    /// Returns the number of live identifiers.
    pub fn len(&self) -> usize {
        self.live.len()
    }

    /// Returns whether no identifier is live.
    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }

    /// Returns a snapshot of the live identifiers for decode admission.
    pub fn live_ids(&self) -> Vec<u64> {
        self.live.iter().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{InFlightRegistry, RegistryError, RequestIdAllocator};

    #[test]
    fn allocation_starts_at_one_and_advances() {
        let mut allocator = RequestIdAllocator::new();
        assert_eq!(allocator.allocate(), 1);
        assert_eq!(allocator.allocate(), 2);
        assert_eq!(allocator.allocate(), 3);
    }

    #[test]
    fn a_live_identifier_is_refused() {
        let mut registry = InFlightRegistry::new();
        assert_eq!(registry.insert(7), Ok(()));
        assert_eq!(registry.insert(7), Err(RegistryError::LiveReuse));
        assert!(registry.contains(7));
    }

    #[test]
    fn the_reserved_identifier_is_refused() {
        let mut registry = InFlightRegistry::new();
        assert_eq!(registry.insert(0), Err(RegistryError::Reserved));
        assert!(!registry.contains(0));
    }

    #[test]
    fn a_retired_identifier_is_reusable_and_releases_once() {
        let mut registry = InFlightRegistry::new();
        assert_eq!(registry.insert(9), Ok(()));
        assert!(registry.retire(9));
        assert!(!registry.contains(9));
        assert_eq!(registry.insert(9), Ok(()));
        assert!(registry.retire(9));
        assert!(!registry.retire(9));
    }

    #[test]
    fn a_second_retire_changes_nothing() {
        let mut registry = InFlightRegistry::new();
        assert!(!registry.retire(42));
        assert_eq!(registry.insert(42), Ok(()));
        assert!(registry.retire(42));
        assert!(!registry.retire(42));
        assert!(registry.is_empty());
    }

    #[test]
    fn wrap_skips_the_reserved_identifier() {
        let mut allocator = RequestIdAllocator::with_start(u64::MAX);
        assert_eq!(allocator.allocate(), u64::MAX);
        assert_eq!(allocator.allocate(), 1);
        assert_eq!(allocator.allocate(), 2);
    }

    #[test]
    fn a_zero_start_allocates_from_one() {
        let mut allocator = RequestIdAllocator::with_start(0);
        assert_eq!(allocator.allocate(), 1);
        assert_eq!(allocator.allocate(), 2);
    }

    #[test]
    fn allocated_identifiers_admit_until_retired() {
        let mut allocator = RequestIdAllocator::new();
        let mut registry = InFlightRegistry::new();
        let first = allocator.allocate();
        let second = allocator.allocate();
        assert_eq!(registry.insert(first), Ok(()));
        assert_eq!(registry.insert(second), Ok(()));
        assert_eq!(registry.len(), 2);
        let mut live = registry.live_ids();
        live.sort_unstable();
        assert_eq!(live, vec![first, second]);
        assert!(registry.retire(first));
        assert_eq!(registry.insert(first), Ok(()));
        assert_eq!(registry.len(), 2);
    }
}

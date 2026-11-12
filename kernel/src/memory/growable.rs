//! Fixed inline storage that is replaced, once, by a larger slice.
//!
//! The frame-role manager and the frame allocator start with arrays sized for
//! boot. Once the kernel's direct map is active they move into one run carved
//! from RAM and sized from installed memory (DW2 large-memory plan, M2 §5.3).
//! The inline array is kept but no longer used after that.

/// `N` inline elements until [`Self::adopt`] switches to a larger slice.
pub(super) struct GrowableStore<T: 'static, const N: usize> {
    inline: [T; N],
    adopted: Option<&'static mut [T]>,
}

impl<T: Copy + 'static, const N: usize> GrowableStore<T, N> {
    pub(super) const fn new(fill: T) -> Self {
        Self {
            inline: [fill; N],
            adopted: None,
        }
    }

    /// Initializes a store in place, so no `N`-element temporary lands on
    /// the bootstrap stack.
    ///
    /// # Safety
    ///
    /// `destination` must be valid for writes of one `Self`.
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    #[allow(
        unsafe_code,
        reason = "in-place construction of a large boot-time array"
    )]
    pub(super) unsafe fn init_in_place(destination: *mut Self, fill: T) {
        unsafe {
            let inline = core::ptr::addr_of_mut!((*destination).inline).cast::<T>();
            for index in 0..N {
                inline.add(index).write(fill);
            }
            core::ptr::addr_of_mut!((*destination).adopted).write(None);
        }
    }

    pub(super) fn as_slice(&self) -> &[T] {
        match &self.adopted {
            Some(adopted) => adopted,
            None => &self.inline,
        }
    }

    pub(super) fn as_mut_slice(&mut self) -> &mut [T] {
        match &mut self.adopted {
            Some(adopted) => adopted,
            None => &mut self.inline,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.as_slice().len()
    }

    pub(super) const fn is_adopted(&self) -> bool {
        self.adopted.is_some()
    }

    /// Moves to `larger`: copies every current element to the same index,
    /// fills the rest with `fill`, and uses `larger` from then on. Refuses
    /// (returning `larger`) a slice that is not larger, or a second adoption.
    pub(super) fn adopt(
        &mut self,
        larger: &'static mut [T],
        fill: T,
    ) -> Result<(), &'static mut [T]> {
        if self.adopted.is_some() || larger.len() <= N {
            return Err(larger);
        }
        larger[..N].copy_from_slice(&self.inline);
        larger[N..].fill(fill);
        self.adopted = Some(larger);
        Ok(())
    }
}

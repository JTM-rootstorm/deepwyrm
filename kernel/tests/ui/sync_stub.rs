pub(crate) struct IrqSpinMutex<T>(std::sync::Mutex<T>);

impl<T> IrqSpinMutex<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self(std::sync::Mutex::new(value))
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, T> {
        self.0.lock().expect("UI fixture lock is not poisoned")
    }
}

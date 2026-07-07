use std::marker::PhantomData;

pub const DEFAULT_CAPACITY: usize = 1000000;

pub struct CuckooFilter<H> {
    _marker: PhantomData<H>,
}

impl<H> CuckooFilter<H> {
    pub fn with_capacity(_cap: usize) -> Self {
        Self {
            _marker: PhantomData,
        }
    }

    pub fn add<T>(&mut self, _item: &T) -> Result<(), ()> {
        Ok(())
    }

    pub fn contains<T>(&self, _item: &T) -> bool {
        false
    }
}

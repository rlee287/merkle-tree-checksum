use merkle_tree::Consumer;

#[derive(Debug, Copy, Clone)]
pub struct ThrowawayConsumer<T> {
    dummy_field: std::marker::PhantomData<T>
}
impl<T> Default for ThrowawayConsumer<T> {
    fn default() -> Self {
        ThrowawayConsumer {
            dummy_field: std::marker::PhantomData::default()
        }
    }
}
impl<T> Consumer<T> for ThrowawayConsumer<T> {
    fn accept(&mut self, _val: T) -> Result<(), T> {
        // Throw away the value
        Ok(())
    }
}

#[derive(Debug)]
pub struct VecCreationConsumer<'a, T> {
    element_vec: &'a mut Vec<T>
}
impl<'a, T> VecCreationConsumer<'a, T> {
    pub fn new(element_vec: &'a mut Vec<T>) -> VecCreationConsumer<'a, T> {
        VecCreationConsumer{
            element_vec: element_vec
        }
    }
}
impl<'a, T> Consumer<T> for VecCreationConsumer<'a, T> {
    fn accept(&mut self, val: T) -> Result<(), T> {
        self.element_vec.push(val);
        Ok(())
    }
}
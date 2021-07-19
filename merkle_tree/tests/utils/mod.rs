use merkle_tree::Consumer;

use std::marker::PhantomData;

#[derive(Debug, Copy, Clone)]
pub struct ThrowawayConsumer<T> {
    dummy_field: PhantomData<T>
}
impl<T> Default for ThrowawayConsumer<T> {
    fn default() -> Self {
        ThrowawayConsumer {
            dummy_field: PhantomData::default()
        }
    }
}
impl<T> Consumer<T> for ThrowawayConsumer<T> {
    fn accept(&self, _val: T) -> Result<(), T> {
        // Throw away the value
        Ok(())
    }
}
/*#[derive(Debug)]
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
    fn accept(&self, val: T) -> Result<(), T> {
        self.element_vec.push(val);
         Ok(())
     }
}*/

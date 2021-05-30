use merkle_tree::{merkle_hash_file, Consumer};

use std::io::Cursor;
use digest::Digest;
use sha2::Sha256;

#[derive(Debug, Copy, Clone)]
struct ThrowawayConsumer<T> {
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
struct VecCreationConsumer<'a, T> {
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

#[test]
fn test_empty_string() {
    let ref_hash = Sha256::digest(b"\x00");
    let ref_hash_ref = ref_hash.as_slice();

    let throwaway_consumer = ThrowawayConsumer::default();
    let empty_cursor = Cursor::new(b"");

    let tree_hash = merkle_hash_file::<_, Sha256, _>
        (empty_cursor, 4, 2, throwaway_consumer);
    let tree_hash_ref = tree_hash.as_ref();
    assert_eq!(ref_hash_ref, tree_hash_ref);
}

#[test]
fn test_partial_block() {
    let ref_hash = Sha256::digest(b"\x00ab");
    let ref_hash_ref = ref_hash.as_slice();

    let throwaway_consumer = ThrowawayConsumer::default();
    let empty_cursor = Cursor::new(b"ab");

    let tree_hash = merkle_hash_file::<_, Sha256, _>
        (empty_cursor, 4, 2, throwaway_consumer);
    let tree_hash_ref = tree_hash.as_ref();
    assert_eq!(ref_hash_ref, tree_hash_ref);
}

#[test]
fn test_tree() {
    let ref_leaf0_hash = Sha256::digest(b"\x00abcd");
    let ref_leaf1_hash = Sha256::digest(b"\x001234");
    let ref_tree_in = [b"\x01",
        ref_leaf0_hash.as_slice(),
        ref_leaf1_hash.as_slice()].concat();
    let ref_tree_hash = Sha256::digest(ref_tree_in.as_slice());

    let mut vec_consumer_backing = Vec::new();
    let vec_consumer = VecCreationConsumer::new(&mut vec_consumer_backing);
    let empty_cursor = Cursor::new(b"abcd1234");

    let tree_hash = merkle_hash_file::<_, Sha256, _>
        (empty_cursor, 4, 2, vec_consumer);
    let tree_hash_ref = tree_hash.as_ref();
    assert_eq!(ref_tree_hash.as_slice(), tree_hash_ref);

    // TODO: check other elements of HashRange too
    assert_eq!(3, vec_consumer_backing.len());
    assert_eq!(ref_leaf0_hash.as_slice(), vec_consumer_backing[0].hash_result.as_ref());
    assert_eq!(ref_leaf1_hash.as_slice(), vec_consumer_backing[1].hash_result.as_ref());
    assert_eq!(ref_tree_hash.as_slice(), vec_consumer_backing[2].hash_result.as_ref());
}
use merkle_tree::{BlockRange, merkle_hash_file};

use std::io::Cursor;
use digest::Digest;
use sha2::Sha256;

use std::str::FromStr;

mod utils;
use utils::*;

#[test]
fn test_blockrange_str_roundtrip() {
    let blockranges_ref = vec![BlockRange::new(0, 3, true),
            BlockRange::new(0x12345678, 0xf0e1d2c3, false)];
    for blockrange_ref in blockranges_ref {
        let stringified = blockrange_ref.to_string();
        let recovered_obj = BlockRange::from_str(&stringified).unwrap();
        assert_eq!(blockrange_ref, recovered_obj);
    }
}

#[test]
fn test_blockrange_bad_str() {
    let blockranges_str_bad = vec!["[034, 0x2124]", "[0x356, 9768)", "garbage"];
    for bad_str in blockranges_str_bad {
        let recovered_obj = BlockRange::from_str(&bad_str);
        assert!(recovered_obj.is_err());
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
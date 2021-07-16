use merkle_tree::{BlockRange, HashRange, merkle_hash_file};

use std::io::Cursor;
use digest::Digest;
use sha2::Sha256;

use std::str::FromStr;

use std::sync::mpsc::channel;

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
        (empty_cursor, 4, 2, throwaway_consumer, false);
    let tree_hash_box = tree_hash.unwrap();
    assert_eq!(ref_hash_ref, tree_hash_box.as_ref());
}

fn test_partial_block_helper(multithread: bool) {
    let ref_hash = Sha256::digest(b"\x00yz");
    let ref_hash_ref = ref_hash.as_slice();

    let throwaway_consumer = ThrowawayConsumer::default();
    let data_cursor = Cursor::new(b"yz");

    let tree_hash = merkle_hash_file::<_, Sha256, _>
        (data_cursor, 4, 2, throwaway_consumer, multithread);
    let tree_hash_box = tree_hash.unwrap();
    assert_eq!(ref_hash_ref, tree_hash_box.as_ref());
}
#[test]
fn test_partial_block() {
    test_partial_block_helper(false);
}
#[test]
fn test_partial_block_threaded() {
    test_partial_block_helper(true);
}

fn test_tree_helper(multithread: bool) {
    let ref_leaf0_hash = Sha256::digest(b"\x00abcd");
    let ref_leaf1_hash = Sha256::digest(b"\x001234");
    let ref_tree_in = [b"\x01",
        ref_leaf0_hash.as_slice(),
        ref_leaf1_hash.as_slice()].concat();
    let ref_tree_hash = Sha256::digest(ref_tree_in.as_slice());

    //let mut vec_consumer_backing = Vec::new();
    //let vec_consumer = VecCreationConsumer::new(&mut vec_consumer_backing);
    let (tx, rx) = channel();
    let data_cursor = Cursor::new(b"abcd1234");

    let tree_hash = merkle_hash_file::<_, Sha256, _>
        (data_cursor, 4, 2, tx, multithread);
    let tree_hash_box = tree_hash.unwrap();

    let vec_consumer_backing: Vec<_> = rx.into_iter().collect();
    assert_eq!(3, vec_consumer_backing.len());
    let ref_leaf0_hashrange = HashRange::new(
        BlockRange::new(0, 0, true),
        BlockRange::new(0, 3, true),
        ref_leaf0_hash.to_vec().into_boxed_slice()
    );
    let ref_leaf1_hashrange = HashRange::new(
        BlockRange::new(1, 1, true),
        BlockRange::new(4, 7, true),
        ref_leaf1_hash.to_vec().into_boxed_slice()
    );
    let ref_tree_hashrange = HashRange::new(
        BlockRange::new(0, 1, true),
        BlockRange::new(0, 7, true),
        ref_tree_hash.to_vec().into_boxed_slice()
    );
    assert_eq!(ref_leaf0_hashrange, vec_consumer_backing[0]);
    assert_eq!(ref_leaf1_hashrange, vec_consumer_backing[1]);
    assert_eq!(ref_tree_hashrange, vec_consumer_backing[2]);

    assert_eq!(ref_tree_hash.as_slice(), tree_hash_box.as_ref());
}
#[test]
fn test_tree() {
    test_tree_helper(false);
}
#[test]
fn test_tree_threaded() {
    test_tree_helper(true);
}

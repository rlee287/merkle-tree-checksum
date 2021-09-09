use merkle_tree::{BlockRange, HashRange, merkle_hash_file};
use merkle_tree::{merkle_block_generator, reorder_hashrange_iter};

use std::io::Cursor;
use std::convert::TryInto;
use digest::Digest;
use sha2::Sha256;

use std::str::FromStr;

use crossbeam_channel::unbounded as unbounded_channel;

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
        (empty_cursor, 4, 2, throwaway_consumer, 0);
    let tree_hash_box = tree_hash.unwrap();
    assert_eq!(ref_hash_ref, tree_hash_box.as_ref());
}

fn test_partial_block_helper(thread_count: usize) {
    let ref_hash = Sha256::digest(b"\x00yz");
    let ref_hash_ref = ref_hash.as_slice();

    let throwaway_consumer = ThrowawayConsumer::default();
    let data_cursor = Cursor::new(b"yz");

    let tree_hash = merkle_hash_file::<_, Sha256, _>
        (data_cursor, 4, 2, throwaway_consumer, thread_count);
    let tree_hash_box = tree_hash.unwrap();
    assert_eq!(ref_hash_ref, tree_hash_box.as_ref());
}
#[test]
fn test_partial_block() {
    test_partial_block_helper(0);
}
#[test]
fn test_partial_block_threaded() {
    test_partial_block_helper(3);
}

fn test_tree_helper(thread_count: usize) {
    let ref_leaf0_hash = Sha256::digest(b"\x00abcd");
    let ref_leaf1_hash = Sha256::digest(b"\x001234");
    let ref_tree_in = [b"\x01",
        ref_leaf0_hash.as_slice(),
        ref_leaf1_hash.as_slice()].concat();
    let ref_tree_hash = Sha256::digest(ref_tree_in.as_slice());

    let (tx, rx) = unbounded_channel();
    let data = b"abcd1234";
    let data_len: u64 = data.len().try_into().unwrap();
    let data_cursor = Cursor::new(data);

    let tree_hash = merkle_hash_file::<_, Sha256, _>
        (data_cursor, 4, 2, tx, thread_count);
    let tree_hash_box = tree_hash.unwrap();

    let rx_iter = rx.into_iter();
    // If not multithread, then should be in order
    // Assume this to make troubleshooting failing tests easier
    let rx_vec: Vec<_> = match thread_count {
        0 => rx_iter.collect(),
        _ => reorder_hashrange_iter(
                merkle_block_generator(data_len, 4, 2).into_iter(),
                rx_iter
            ).into_iter().collect()
        };
    assert_eq!(3, rx_vec.len());
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
    assert_eq!(ref_leaf0_hashrange, rx_vec[0]);
    assert_eq!(ref_leaf1_hashrange, rx_vec[1]);
    assert_eq!(ref_tree_hashrange, rx_vec[2]);

    assert_eq!(ref_tree_hash.as_slice(), tree_hash_box.as_ref());
}
#[test]
fn test_tree() {
    test_tree_helper(0);
}
#[test]
fn test_tree_threaded() {
    test_tree_helper(3);
}

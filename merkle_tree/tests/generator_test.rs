use merkle_tree::{BlockRange, merkle_block_generator, reorder_hashrange_iter};
use merkle_tree::{HashRange, merkle_hash_file};

use sha2::Sha256;
use permutohedron::Heap;

use std::convert::TryInto;
use std::io::Cursor;

use crossbeam_channel::unbounded as unbounded_channel;

#[test]
fn test_empty_iter() {
    let mut block_iter = merkle_block_generator(0, 4, 2).into_iter();
    let empty_block = block_iter.next().unwrap();
    assert_eq!(empty_block, BlockRange::new(0, 0, true));
    assert!(block_iter.next().is_none());
}

#[test]
fn test_tree_iter() {
    let (tx, rx) = unbounded_channel();
    let data = b"abcd12345";
    let data_len: u64 = data.len().try_into().unwrap();
    let data_cursor = Cursor::new(data);

    merkle_hash_file::<_, Sha256, _>
        (data_cursor, 4, 2, tx, 0).unwrap();
    for (blockrange, hashrange) in merkle_block_generator(data_len, 4, 2)
        .into_iter().zip(rx.into_iter()) {
            assert_eq!(blockrange, hashrange.block_range());
    }
}

#[test]
fn reorder_already_ordered() {
    let blockrange_vec = vec![
        BlockRange::new(0, 0, true),
        BlockRange::new(1, 1, true),
        BlockRange::new(2, 2, true),
        BlockRange::new(3, 3, true)
    ];
    let hashrange_vec: Vec<_> = blockrange_vec.iter()
        .map(|blockrange| {
            let dummy_byterange = BlockRange::new(16, 16, true);
            let dummy_hash = vec![0x00, 0xff].into_boxed_slice();
            HashRange::new(*blockrange, dummy_byterange, dummy_hash)
        }).collect();
    let hashrange_vec_ref = hashrange_vec.clone();
    let sorted_hashrange_vec: Vec<_> = reorder_hashrange_iter(
        blockrange_vec.into_iter(), hashrange_vec.into_iter()).into_iter().collect();
    assert_eq!(hashrange_vec_ref, sorted_hashrange_vec);
}
#[test]
fn reorder_scrambled() {
    let blockrange_vec = vec![
        BlockRange::new(0, 8, false),
        BlockRange::new(1, 9, false),
        BlockRange::new(2, 10, true),
        BlockRange::new(3, 11, true)
    ];
    let mut hashrange_vec: Vec<_> = blockrange_vec.iter()
        .map(|blockrange| {
            let dummy_byterange = BlockRange::new(16, 16, true);
            let dummy_hash = vec![0x00, 0xff].into_boxed_slice();
            HashRange::new(*blockrange, dummy_byterange, dummy_hash)
        }).collect();
    let hashrange_vec_ref = hashrange_vec.clone();

    let shuffler = Heap::new(&mut hashrange_vec);
    for ordering in shuffler {
        let blockrange_vec_iter = blockrange_vec.clone().into_iter();
        let hashrange_vec_iter = ordering.clone().into_iter();
        let sorted_hashrange_vec: Vec<_> = reorder_hashrange_iter(
            blockrange_vec_iter, hashrange_vec_iter).into_iter().collect();
        assert_eq!(hashrange_vec_ref, sorted_hashrange_vec);
    }
}
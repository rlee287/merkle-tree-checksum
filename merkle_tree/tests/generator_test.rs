use merkle_tree::{BlockRange, merkle_block_generator, merkle_hash_file};

use sha2::Sha256;

mod utils;

use std::convert::TryInto;
use std::io::Cursor;

use std::sync::mpsc::channel;

#[test]
fn test_empty_iter() {
    let mut block_iter = merkle_block_generator(0, 4, 2).into_iter();
    let empty_block = block_iter.next().unwrap();
    assert_eq!(empty_block, BlockRange::new(0, 0, true));
    assert!(block_iter.next().is_none());
}

#[test]
fn test_tree_iter() {
    let (tx, rx) = channel();
    let data = b"abcd12345";
    let data_len: u64 = data.len().try_into().unwrap();
    let data_cursor = Cursor::new(data);

    merkle_hash_file::<_, Sha256, _>
        (data_cursor, 4, 2, tx, false).unwrap();
    for (blockrange, hashrange) in merkle_block_generator(data_len, 4, 2)
        .into_iter().zip(rx.into_iter()) {
            assert_eq!(blockrange, hashrange.block_range());
    }
}
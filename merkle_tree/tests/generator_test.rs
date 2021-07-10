use merkle_tree::{merkle_block_generator, merkle_hash_file};

use sha2::Sha256;

mod utils;
use utils::VecCreationConsumer;

use std::convert::TryInto;
use std::io::Cursor;

#[test]
fn test_tree_iter() {
    let mut vec_consumer_backing = Vec::new();
    let vec_consumer = VecCreationConsumer::new(&mut vec_consumer_backing);
    let data = b"abcd12345";
    let data_len: u64 = data.len().try_into().unwrap();
    let data_cursor = Cursor::new(data);

    merkle_hash_file::<_, Sha256, _>
        (data_cursor, 4, 2, vec_consumer).unwrap();
    for (blockrange, hashrange) in merkle_block_generator(data_len, 4, 2)
        .into_iter().zip(vec_consumer_backing.into_iter()) {
            assert_eq!(blockrange, hashrange.block_range());
    }
}
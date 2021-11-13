use std::io::{Read, Seek, SeekFrom, ErrorKind};
use std::fs::File;

use std::path::PathBuf;

use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

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

pub fn gen_random_name(prefix: &str) -> PathBuf {
    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    let output_name = prefix.to_owned() + &rand_string;
    PathBuf::from(output_name)
}

pub fn file_contents_equal(mut file1: File, mut file2: File) -> bool {
    let file1_metadata = file1.metadata().unwrap();
    let file2_metadata = file2.metadata().unwrap();
    if file1_metadata.len() != file2_metadata.len() {
        return false;
    }

    let mut file1_remainder: Vec<u8> = Vec::new();
    let mut file2_remainder: Vec<u8> = Vec::new();

    file1.seek(SeekFrom::Start(0)).unwrap();
    file2.seek(SeekFrom::Start(0)).unwrap();

    loop {
        let mut file1_block: [u8; 4096] = [0; 4096];
        let file1_seek_pos = file1.stream_position().unwrap();
        let file1_read_result = file1.read_exact(&mut file1_block);

        let mut file2_block: [u8; 4096] = [0; 4096];
        let file2_seek_pos = file2.stream_position().unwrap();
        let file2_read_result = file2.read_exact(&mut file2_block);

        if file1_read_result.is_ok() && file2_read_result.is_ok() {
            if file1_block != file2_block {
                return false;
            }
        // Fix the matches stuff
        } else if let (Err(file1_err), Err(file2_err)) = (file1_read_result, file2_read_result) {
            // UnexpectedEof -> cursor seek position is unspecified
            assert!(file1_err.kind() == ErrorKind::UnexpectedEof);
            assert!(file2_err.kind() == ErrorKind::UnexpectedEof);
            // Reset to known good point before reading in the rest
            file1.seek(SeekFrom::Start(file1_seek_pos)).unwrap();
            file2.seek(SeekFrom::Start(file2_seek_pos)).unwrap();

            file1.read_to_end(&mut file1_remainder).unwrap();
            file2.read_to_end(&mut file2_remainder).unwrap();
            if file1_block != file2_block {
                return false;
            } else {
                return true;
            }
        } else {
            panic!("{}", "Error reading from one of the files");
        }
    }
}
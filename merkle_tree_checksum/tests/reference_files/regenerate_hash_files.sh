#!/bin/sh
cargo run -- generate-hash -l 4 --overwrite -o hash_out -- 16_byte_file 20_byte_file empty_file
cargo run -- generate-hash -l 4 --overwrite -s -o hash_out_short -- 16_byte_file 20_byte_file empty_file

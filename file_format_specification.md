# Output File Format (Text)

The output file starts with the program version, followed by options. Afterwards, the output lists the hashes associated with each file.

The version is printed as `merkle_tree_checksum v{version}`.

The options for computing the hash tree are then printed, with a format like below (where the items may be in any order):

```
Hash function: sha256
Block size: 4
Branching factor: 4
```

When in `--short` mode, the output follows the format used by tools like `sha256sum`: the root hash is printed on a line, followed by a quoted file name. An example line is:

```
deadbeef  "crc32_moo.txt"
```

When not in `--short` mode, the files are first listed in a separate `File: ` section, where each entry is a quoted file name, followed by the size of the file in hexadecimal, such as follows:

```
"16_byte_file.txt" 0x10 bytes
```

Each hash is then printed with the following format:

```
[file_index] [{tree_block_start}-{tree_block_end}] [{file_byte_start}-{file_byte_end}] {hash}
```

where the file index is a 0-indexed position from the file list printed earlier. `tree_block_start` and `tree_block_end` indicate the indicies of blocks covered by the hash in the tree structure, and `file_byte_start` and `file_byte_end` indicate the range of bytes covered by the hash.  `tree_block_end` may point to a block end past the actual end-of-file when the file's block count is not a power of `branch_factor`.)

# Output File Format (Binary)

Not yet implemented

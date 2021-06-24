# merkle-tree-checksum

This is a utility that computes a Merkle tree hash over the specified files. The advantage that a Merkle tree has over applying the hash once includes

* Hash parallelism (which is not taken advantage of yet)
* Precisely identifying which blocks have been corrupted

## Hash Tree Structure

The file is first divided into blocks that are `block_length` bytes long, and each block is hashed to create the leaf nodes of the tree. Adjacent nodes at each layer are grouped into groups of `branch_factor` nodes, and a hash is computed for a parent node (with these nodes as children) by hashing the concatenation of the hashes in the children nodes. (A parent node may have less than `branch_factor` children when the total number of blocks is not a power of `branch_factor`.)

To address second pre-image attacks, we prepend the byte `0x00` before hashing data blocks, and prepend `0x01` before hashing the concatenation of node hashes. (This is the same data adjustment used in Certificate Transparency.)

## Output File Format

The output file starts with the program version, followed by options. Afterwards, the output lists the hashes associated with each file.

The version is printed as `merkle_tree_checksum v{version}`.

The options for computing the hash tree are then printed, with a format like below (where the items may be in any order):

```
Hash function: sha256
Block size: 4
Branching factor: 4
```

When in `--short` mode, the output follows the format used by tools like `sha256sum`: the root hash is printed on a line, followed by a quoted file name.

When not in `--short` mode, the files are first listed in a separate `File: `, where each entry is a quoted file name. Each hash is then printed with the following format:

```
[file_index] [{tree_block_start}-{tree_block_end}] [{file_byte_start}-{file_byte_end}] {hash}
```

where the file index is a 0-indexed position from the file list printed earlier. `tree_block_start` and `tree_block_end` indicate the indicies of blocks covered by the hash in the tree structure, and `file_byte_start` and `file_byte_end` indicate the range of bytes covered by the hash.  `tree_block_end` may point to a block end past the actual end-of-file when the file's block count is not a power of `branch_factor`.)

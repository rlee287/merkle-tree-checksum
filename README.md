# merkle-tree-checksum

This is a utility that computes a Merkle tree hash over the specified files. The advantage that a Merkle tree has over applying the hash once includes

* Hash parallelism (which is not taken advantage of yet)
* Precisely identifying which blocks have been corrupted

## Hash Tree Structure

The file is first divided into blocks that are `block_length` bytes long, and each block is hashed to create the leaf nodes of the tree. Adjacent nodes at each layer are grouped into groups of `branch_factor` nodes, and a hash is computed for a parent node (with these nodes as children) by hashing the concatenation of the hashes in the children nodes. (A parent node may have less than `branch_factor` children when the total number of blocks is not a power of `branch_factor`.)

To address second pre-image attacks, we prepend the byte `0x00` before hashing data blocks, and prepend `0x01` before hashing the concatenation of node hashes. (This is the same data adjustment used in Certificate Transparency.)

## Output File Format

The output file starts with the program version, options, and a timestamp. Afterwards, the output lists the hashes associated with each file.

The version is printed as `merkle_tree_checksum v{version}`.

The options (excluding the actual file list) are printed as passed into the command line with the prefix string `Arguments: `.

The timestamp is printed as `Started `, followed by a timestamp in RFC 2822 format.

When in `--short` mode, the output follows the format used by tools like `sha256sum`: the root hash is printed on a line, followed by the file name.

When not in `--short` mode, the file name is first declared on its own line with `File `, followed by the file name. Each hash is then printed with the following format:

```
[{tree_block_start}-{tree_block_end}] [{file_block_start}-{file_block_end}] {hash}
```

where the blocks' start and end indicate which bytes are included in the given hash. (`tree_block_end` indicates the end of the bytes covered by the tree structure, and may be larger than `file_block_end` when the file's block count is not a power of `branch_factor`.)

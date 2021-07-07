# merkle-tree-checksum

This is a utility that computes a Merkle tree hash over the specified files. The advantage that a Merkle tree has over applying the hash once includes

* Hash parallelism (which is not taken advantage of yet)
* Precisely identifying which blocks have been corrupted

## Hash Tree Structure

The file is first divided into blocks that are `block_length` bytes long, and each block is hashed to create the leaf nodes of the tree. Adjacent nodes at each layer are grouped into groups of `branch_factor` nodes, and a hash is computed for a parent node (with these nodes as children) by hashing the concatenation of the hashes in the children nodes. (A parent node may have less than `branch_factor` children when the total number of blocks is not a power of `branch_factor`.)

To address second pre-image attacks, we prepend the byte `0x00` before hashing data blocks, and prepend `0x01` before hashing the concatenation of node hashes. (This is the same data adjustment used in Certificate Transparency.)

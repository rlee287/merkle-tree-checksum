#!/bin/bash
declare -a hash_arr=("crc32"
    "sha224" "sha256" "sha384" "sha512" "sha512_224" "sha512_256"
    "sha3_224" "sha3_256" "sha3_384" "sha3_512"
    "blake2b512" "blake2s256"
    "blake3")
for hash_func in "${hash_arr[@]}"
do
    file_name="$hash_func"
    file_name+='_gen_ref'
    dir_name=$file_name
    file_name+='.toml'
    dir_name+='.in'
    echo "Generating $file_name"
    gpp -DHASH_FUNC=$hash_func -o $file_name template_gen_ref_long.toml.gpp
    echo "Populating $dir_name"
    if [ ! -d "$dir_name" ]; then
        mkdir "$dir_name"
    fi
    cp ../reference_files/16_byte_file "$dir_name/"
    cp ../reference_files/20_byte_file "$dir_name/"
    cp ../reference_files/empty_file "$dir_name/"
done
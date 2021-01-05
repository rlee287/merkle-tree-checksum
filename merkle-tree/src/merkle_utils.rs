use generic_array::{GenericArray, ArrayLength};

pub(crate) fn ceil_div(num: u64, denom: u64) -> u64 {
    let result = num / denom;
    // return
    match num % denom {
        0 => result,
        _ => result + 1
    }
}
pub(crate) fn exp_ceil_log(number: u64, base: u16) -> u64 {
    let base_as_u64: u64 = base.into();
    let mut result = 1;
    while result < number {
        result = result * base_as_u64;
    }
    // return
    result
}

pub(crate) fn print_arr<N>(prefix_str: &str, arr: &GenericArray<u8, N>)
where
    N: ArrayLength<u8>
{
    print!("{}", prefix_str);
    for byte_val in arr {
        print!("{:02x}", byte_val);
    }
    print!("\n");
}
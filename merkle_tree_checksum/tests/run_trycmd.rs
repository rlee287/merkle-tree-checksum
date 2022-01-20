#[test]
fn gen_ref_tests() {
    trycmd::TestCases::new()
        .case("tests/gen_ref/*_gen_ref.toml");
}

#[test]
fn help_test() {
    trycmd::TestCases::new()
        .case("tests/help_cmd/help_out_*.toml");
}
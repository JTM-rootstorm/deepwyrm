fn main() {
    if let Err(error) = abi_gen::run(std::env::args_os().skip(1)) {
        eprintln!("abi-gen: {error}");
        std::process::exit(1);
    }
}

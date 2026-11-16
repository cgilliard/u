//! Makes a network's genesis block. Not written yet: mainnet's testing
//! genesis is the one the original's tool wrote (`tabminer::genesis`),
//! and a real one is made just before launch.

fn main() {
    eprintln!("genesis: not built yet (the genesis in use is {})", tabminer::genesis::ID);
    std::process::exit(-1);
}

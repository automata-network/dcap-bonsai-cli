pub mod code;
pub mod collaterals;
pub mod chain;
pub mod constants;
pub mod parser;

// Shared methods go here...

pub fn remove_prefix_if_found(h: &str) -> &str {
    if h.starts_with("0x") {
        &h[2..]
    } else {
        &h
    }
}
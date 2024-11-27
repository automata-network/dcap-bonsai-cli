pub mod chain;
pub mod constants;
pub mod parser;

pub fn remove_prefix_if_found(h: &str) -> &str {
    h.trim_start_matches("0x")
}

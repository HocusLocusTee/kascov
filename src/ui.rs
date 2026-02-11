use std::fmt::Display;

pub fn print_header(title: &str) {
    println!("== {title} ==");
}

pub fn print_kv(key: &str, value: impl Display) {
    println!("{key:>26}: {value}");
}

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use std::fs::{self, File};
use object::{Object, ObjectSymbol};
use anyhow::anyhow;

pub fn get_symbol_address(path: &PathBuf, fn_name: &str) -> anyhow::Result<u64> {
    let buffer = fs::read(path)?;
    let file = object::File::parse(buffer.as_slice())?;
    let mut symbols = file.symbols();
    // -----------------------------------

    let symbol = symbols
        .find(|symbol| {
            if let Ok(name) = symbol.name() {
                return name == fn_name;
            }
            false
        })
        .ok_or_else(|| anyhow!("symbol not found: {}", fn_name))?;

    Ok(symbol.address() as u64)
}

pub fn get_load_base(pid: u32, binary: &str) -> Option<u64> {
    let maps_path = format!("/proc/{}/maps", pid);
    let file = File::open(maps_path).ok()?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line.ok()?;
        if line.contains(binary) {
            // line format: 00400000-00adc000 r-xp 00000000 103:02 10359059 /path/to/binary
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(range) = parts.get(0) {
                let addr_str = range.split('-').next()?;
                if let Ok(addr) = u64::from_str_radix(addr_str, 16) {
                    return Some(addr);
                }
            }
        }
    }
    None
}

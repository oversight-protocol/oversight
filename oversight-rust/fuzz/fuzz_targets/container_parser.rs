#![no_main]
use libfuzzer_sys::fuzz_target;
use oversight_container::SealedFile;

// Hammer the binary parser with arbitrary bytes.
// Must never panic, OOM, or infinite-loop: all malformed inputs should
// return a clean ContainerError.
fuzz_target!(|data: &[u8]| {
    let _ = SealedFile::from_bytes(data);
});

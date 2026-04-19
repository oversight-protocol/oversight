#![no_main]
use libfuzzer_sys::fuzz_target;
use oversight_manifest::Manifest;

fuzz_target!(|data: &[u8]| {
    let _ = Manifest::from_json(data);
});

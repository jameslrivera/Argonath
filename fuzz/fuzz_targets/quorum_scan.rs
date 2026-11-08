#![no_main]

use anchor_lang::prelude::Pubkey;
use collateral::quorum::scan_quorum;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let admins = [
        Pubkey::new_from_array([1u8; 32]),
        Pubkey::new_from_array([2u8; 32]),
        Pubkey::new_from_array([3u8; 32]),
    ];
    let digest = [7u8; 32];
    let _ = scan_quorum(data, &admins, &digest, 2, true);
    let _ = scan_quorum(data, &admins, &digest, 2, false);
});

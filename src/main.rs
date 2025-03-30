use std::io::{self, Write};
use std::process;
extern crate bitcoin;
extern crate secp256k1;
use bitcoin::util::bip32;
use bitcoin::util::base58::FromBase58;
use bitcoin::util::base58::ToBase58;
use secp256k1::{Secp256k1, key::SecretKey};

fn main() {
    println!("Enter: <xpub> <derivation_index> <child_privkey>");
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_) => {}
        Err(error) => {
            writeln!(::std::io::stderr(), "{}", error).ok();
            process::exit(1);
        }
    }
    let v: Vec<&str> = input.trim().split(' ').collect();
    if v.len() != 3 {
        eprintln!("Invalid input. Expected: <xpub> <derivation_index> <child_privkey>");
        process::exit(1);
    }

    let xpub_str = v[0];
    let index_str = v[1];
    let child_privkey_str = v[2].trim();

    let extpub_result = match bip32::ExtendedPubKey::from_base58check(xpub_str) {
        Ok(xpub) => xpub,
        Err(e) => {
            eprintln!("Invalid xpub: {}", e);
            process::exit(1);
        }
    };

    let index = match index_str.parse::<u32>() {
        Ok(idx) => idx,
        Err(e) => {
            eprintln!("Invalid derivation index: {}", e);
            process::exit(1);
        }
    };

    let child_privkey = match bitcoin::util::address::Privkey::from_base58check(child_privkey_str) {
        Ok(privkey) => privkey,
        Err(e) => {
            eprintln!("Invalid child private key: {}", e);
            process::exit(1);
        }
    };

    let network = bitcoin::network::constants::Network::Bitcoin;
    let ctx = Secp256k1::new();

    // Calculate the tweak
    let child_tweak_and_chaincode = extpub_result
        .ckd_pub_tweak(&ctx, bip32::ChildNumber::Normal(index))
        .unwrap();

    let mut child_tweak = child_tweak_and_chaincode.0;

    // Invert the tweak
    let neg_tweak = child_tweak.negate(&ctx);

    // Subtract the tweak from the child private key to get the parent private key.
    let mut child_secret = child_privkey.secret_key().clone();

    let parent_secret = match child_secret.add_tweak(&ctx, &neg_tweak) {
        Ok(secret) => secret,
        Err(e) => {
            eprintln!("Error adding secret keys: {:?}", e);
            process::exit(1);
        }
    };

    // Construct the parent xprv
    let fingerprint: [u8; 4] = [0; 4];
    let finger = bip32::Fingerprint::from(&fingerprint[..]);
    let xprv = bip32::ExtendedPrivKey {
        chain_code: extpub_result.chain_code,
        child_number: bip32::ChildNumber::Normal(0),
        depth: 0,
        parent_fingerprint: finger,
        secret_key: parent_secret,
        network,
    };

    println!("{}", xprv.to_base58check());
}


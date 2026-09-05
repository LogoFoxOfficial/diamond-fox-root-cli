use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    compile_windows_resources();
    println!("cargo:rerun-if-env-changed=DIAMONDFOX_RELEASE_SPEC");
    println!("cargo:rerun-if-env-changed=DIAMONDFOX_EMBED_KEY_FILE");
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let spec_path = env::var_os("DIAMONDFOX_RELEASE_SPEC")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("private/release.json"));
    if !spec_path.is_file() {
        fs::write(output.join("builtins.rs"), empty_generated()).unwrap();
        return;
    }
    println!("cargo:rerun-if-changed={}", spec_path.display());
    let key_path = env::var_os("DIAMONDFOX_EMBED_KEY_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("private/embed-key.hex"));
    println!("cargo:rerun-if-changed={}", key_path.display());
    let key = decode_key(&key_path);
    let spec: Value = serde_json::from_slice(&fs::read(&spec_path).unwrap()).unwrap();
    let key_mask: [u8; 32] = Sha256::digest([b"DiamondFox key mask v1", key.as_slice()].concat())
        .as_slice()
        .try_into()
        .unwrap();
    let mut masked_key = [0u8; 32];
    for index in 0..32 {
        masked_key[index] = key[index] ^ key_mask[index];
    }
    let mut generated = format!(
        "pub const EMBED_KEY_MASK: [u8; 32] = {key_mask:?};\npub const EMBED_KEY_MASKED: [u8; 32] = {masked_key:?};\n"
    );
    generated.push_str("pub static HOST_FILES: &[GeneratedHostFile] = &[\n");
    for (index, host) in array(&spec, "host_files").iter().enumerate() {
        let name = string(host, "name");
        let expected = string(host, "sha256");
        let source = source_path(&root, string(host, "source"));
        let data = verified_source(&source, expected);
        let output_name = format!("host-{index}.bin");
        fs::write(output.join(&output_name), data).unwrap();
        generated.push_str(&format!(
            "GeneratedHostFile {{ name: {name:?}, bytes: include_bytes!({output_name:?}), sha256: {expected:?} }},\n"
        ));
    }
    generated.push_str("];\n");
    generated.push_str("pub fn generated_packages() -> Vec<GeneratedPackage> { vec![\n");
    let mut asset_index = 0usize;
    for package in array(&spec, "packages") {
        let manifest = package.get("manifest").expect("package manifest");
        let manifest_json = serde_json::to_string(manifest).unwrap();
        let sources: HashMap<String, String> =
            serde_json::from_value(package.get("sources").cloned().unwrap()).unwrap();
        generated.push_str(&format!(
            "GeneratedPackage {{ manifest_json: {manifest_json:?}, assets: vec![\n"
        ));
        for asset in array(manifest, "assets") {
            let role = string(asset, "role");
            let expected = string(asset, "sha256");
            let source_value = sources.get(role).expect("asset source");
            let source = source_path(&root, source_value);
            let plaintext = verified_source(&source, expected);
            let nonce = nonce_for(&manifest_json, role, expected);
            let ciphertext = crypt(&key, &nonce, &plaintext);
            let tag = auth_tag(&key, &nonce, &ciphertext);
            let output_name = format!("asset-{asset_index}.bin");
            fs::write(output.join(&output_name), ciphertext).unwrap();
            generated.push_str(&format!(
                "GeneratedAsset {{ role: {role:?}, ciphertext: include_bytes!({output_name:?}), nonce: {nonce:?}, tag: {tag:?} }},\n"
            ));
            asset_index += 1;
        }
        generated.push_str("] },\n");
    }
    generated.push_str("] }\n");
    fs::write(output.join("builtins.rs"), generated).unwrap();
}

fn empty_generated() -> &'static str {
    "pub const EMBED_KEY_MASK: [u8; 32] = [0; 32];\npub const EMBED_KEY_MASKED: [u8; 32] = [0; 32];\npub static HOST_FILES: &[GeneratedHostFile] = &[];\npub fn generated_packages() -> Vec<GeneratedPackage> { Vec::new() }\n"
}

fn compile_windows_resources() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    println!("cargo:rerun-if-changed=DiamondFox.exe.manifest");
    let mut resource = winres::WindowsResource::new();
    resource.set("ProductName", "DiamondFox Root CLI");
    resource.set("FileDescription", "DiamondFox Root CLI");
    resource.set("CompanyName", "DiamondFox");
    resource.set(
        "LegalCopyright",
        "Copyright (c) 2026 DiamondFox contributors",
    );
    resource.set_manifest_file("DiamondFox.exe.manifest");
    resource.compile().expect("compile Windows resources");
}

fn array<'a>(value: &'a Value, name: &str) -> &'a Vec<Value> {
    value.get(name).and_then(Value::as_array).unwrap()
}

fn string<'a>(value: &'a Value, name: &str) -> &'a str {
    value.get(name).and_then(Value::as_str).unwrap()
}

fn source_path(root: &Path, source: &str) -> PathBuf {
    let path = PathBuf::from(source);
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

fn decode_key(path: &Path) -> [u8; 32] {
    let bytes = hex::decode(fs::read_to_string(path).unwrap().trim()).unwrap();
    bytes.try_into().expect("embed key must contain 32 bytes")
}

fn verified_source(path: &Path, expected: &str) -> Vec<u8> {
    println!("cargo:rerun-if-changed={}", path.display());
    let data = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let actual = hex::encode_upper(Sha256::digest(&data));
    assert_eq!(actual, expected, "hash mismatch for {}", path.display());
    data
}

fn nonce_for(manifest: &str, role: &str, hash: &str) -> [u8; 16] {
    let digest = Sha256::digest([manifest.as_bytes(), role.as_bytes(), hash.as_bytes()].concat());
    digest[..16].try_into().unwrap()
}

fn crypt(key: &[u8; 32], nonce: &[u8; 16], input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    for (counter, chunk) in input.chunks(32).enumerate() {
        let mut message = b"DiamondFox stream v1".to_vec();
        message.extend_from_slice(nonce);
        message.extend_from_slice(&(counter as u64).to_be_bytes());
        let block = hmac(key, &message);
        output.extend(
            chunk
                .iter()
                .zip(block.iter())
                .map(|(left, right)| left ^ right),
        );
    }
    output
}

fn auth_tag(key: &[u8; 32], nonce: &[u8; 16], ciphertext: &[u8]) -> [u8; 32] {
    let mut message = b"DiamondFox asset v1".to_vec();
    message.extend_from_slice(nonce);
    message.extend_from_slice(ciphertext);
    hmac(key, &message)
}

fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..key.len()].copy_from_slice(key);
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for index in 0..64 {
        inner[index] ^= block[index];
        outer[index] ^= block[index];
    }
    let inner_hash = Sha256::digest([inner.as_slice(), message].concat());
    Sha256::digest([outer.as_slice(), inner_hash.as_slice()].concat())
        .as_slice()
        .try_into()
        .unwrap()
}

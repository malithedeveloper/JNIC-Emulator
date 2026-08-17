use crate::classfile::{Constant, JavaClass, JavaMethod};
use crate::pe::{PeImage, RuntimeFunction};

#[derive(Debug, Clone)]
pub struct LoaderSecrets {
    pub global_rva: u32,
    pub stream_len: usize,
    pub keystream: Vec<u8>,
}

const MARKER: &[u8] = b" jnic.dev v";

pub fn recover_loader_secrets(
    image: &PeImage,
    classes: &[JavaClass],
) -> Result<LoaderSecrets, String> {
    let onload_rva = image
        .exports
        .iter()
        .find(|export| export.name == "JNI_OnLoad")
        .map(|export| export.rva)
        .ok_or("JNI_OnLoad export not found")?;
    let function = image
        .function_at(onload_rva)
        .ok_or("JNI_OnLoad has no runtime-function boundary")?;
    let length = usize::try_from(function.end - function.begin).map_err(|e| e.to_string())?;
    let code = image
        .slice(function.begin, length)
        .map_err(|e| e.to_string())?;

    let (key, constants) = recover_chacha_key_and_constants(image)?;
    let nonce = loader_nonce(classes).ok_or("loader direct-buffer nonce not found")?;
    let global_rva = recover_keystream_global(image, function, code)?;
    let stream_len = recover_stream_length(code).unwrap_or(10449);
    let keystream = chacha20_stream(&constants, &key, &nonce, stream_len);
    Ok(LoaderSecrets {
        global_rva,
        stream_len,
        keystream,
    })
}

fn recover_chacha_key_and_constants(image: &PeImage) -> Result<([u8; 32], [u8; 16]), String> {
    let marker_pos = image
        .bytes()
        .windows(MARKER.len())
        .position(|window| window == MARKER)
        .ok_or("JNIC constant marker not found")?;
    let key_pos = marker_pos.checked_sub(32).ok_or("truncated key offset")?;
    let key_bytes = image
        .bytes()
        .get(key_pos..key_pos + 32)
        .ok_or("truncated ChaCha key")?;
    let const_bytes = image
        .bytes()
        .get(marker_pos..marker_pos + 16)
        .ok_or("truncated ChaCha constants")?;
    let mut key = [0_u8; 32];
    key.copy_from_slice(key_bytes);
    let mut constants = [0_u8; 16];
    constants.copy_from_slice(const_bytes);
    Ok((key, constants))
}

fn recover_keystream_global(
    image: &PeImage,
    function: RuntimeFunction,
    code: &[u8],
) -> Result<u32, String> {
    for index in 0..code.len().saturating_sub(7) {
        if code[index] != 0x48 || code[index + 1] != 0x89 || code[index + 2] != 0x05 {
            continue;
        }
        let displacement = i32::from_le_bytes(
            code[index + 3..index + 7]
                .try_into()
                .map_err(|_| "short global displacement".to_owned())?,
        );
        let target = i64::from(function.begin)
            .checked_add(i64::try_from(index).map_err(|e| e.to_string())?)
            .and_then(|value| value.checked_add(i64::from(displacement) + 7))
            .ok_or("global RVA overflow")?;
        if let Ok(target) = u32::try_from(target) {
            if image
                .section_for(target)
                .is_some_and(|section| section.name == ".data")
            {
                return Ok(target);
            }
        }
    }
    Err("keystream global not recognized".to_string())
}

fn recover_stream_length(code: &[u8]) -> Option<usize> {
    let mut best = None;
    for index in 0..code.len().saturating_sub(7) {
        if code[index] != 0x48 || code[index + 1] != 0x81 || code[index + 2] != 0xFA {
            continue;
        }
        let value = u32::from_le_bytes(code.get(index + 3..index + 7)?.try_into().ok()?);
        if (4096..=64 * 1024 * 1024).contains(&value) {
            best = Some(best.map_or(value, |old: u32| old.max(value)));
        }
    }
    best.and_then(|value| usize::try_from(value).ok())
}

fn loader_nonce(classes: &[JavaClass]) -> Option<[u8; 12]> {
    let loader = classes.iter().find(|class| {
        !class.dat_resources.is_empty()
            && class.methods.iter().any(|method| method.name == "<clinit>")
    })?;
    let clinit = loader
        .methods
        .iter()
        .find(|method| method.name == "<clinit>")?;
    let values = all_put_int_values(loader, clinit);
    if values.len() < 3 {
        return None;
    }
    let target_slice = if values.len() >= 11 {
        &values[8..11]
    } else {
        &values[0..3]
    };
    let mut nonce = [0_u8; 12];
    for (index, word) in target_slice.iter().enumerate() {
        nonce[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Some(nonce)
}

fn all_put_int_values(class: &JavaClass, method: &JavaMethod) -> Vec<i32> {
    let mut values = Vec::new();
    let mut pending: Option<i32> = None;
    for pc in java_instruction_offsets(&method.code) {
        let Some(opcode) = method.code.get(pc).copied() else {
            break;
        };
        if let Some(value) = pushed_int_constant(class, &method.code, pc, opcode) {
            pending = Some(value);
            continue;
        }
        if matches!(opcode, 0xB6..=0xB9) {
            let index = method
                .code
                .get(pc + 1..pc + 3)
                .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
                .map(u16::from_be_bytes)
                .unwrap_or(u16::MAX);
            if let Some(member) = class.resolve_member(index) {
                if member.name == "putInt" && member.descriptor.starts_with("(I)") {
                    if let Some(value) = pending.take() {
                        values.push(value);
                    }
                    continue;
                }
            }
        }
        if !matches!(opcode, 0xB2 | 0xB6 | 0xB7 | 0xB8 | 0xB9 | 0x57 | 0x58) {
            pending = None;
        }
    }
    values
}

fn pushed_int_constant(class: &JavaClass, code: &[u8], pc: usize, opcode: u8) -> Option<i32> {
    match opcode {
        0x02..=0x08 => Some(i32::from(opcode) - 3),
        0x10 => code.get(pc + 1).map(|byte| i32::from(*byte as i8)),
        0x11 => code
            .get(pc + 1..pc + 3)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .map(|bytes| i16::from_be_bytes(bytes).into()),
        0x12 | 0x13 => {
            let index = if opcode == 0x12 {
                usize::from(code.get(pc + 1).copied()?)
            } else {
                usize::from(u16::from_be_bytes(
                    code.get(pc + 1..pc + 3)?.try_into().ok()?,
                ))
            };
            match class.pool.get(index)? {
                Constant::Integer(value) => Some(*value),
                _ => None,
            }
        }
        _ => None,
    }
}

fn java_instruction_offsets(code: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut pc = 0_usize;
    while pc < code.len() {
        offsets.push(pc);
        let Some(opcode) = code.get(pc).copied() else {
            break;
        };
        let Some(length) = java_instruction_length(code, pc, opcode) else {
            break;
        };
        pc = match pc.checked_add(length) {
            Some(next) if next < code.len() => next,
            _ => break,
        };
    }
    offsets
}

fn java_instruction_length(code: &[u8], pc: usize, opcode: u8) -> Option<usize> {
    match opcode {
        0x10 | 0x12 | 0x15..=0x19 | 0x36..=0x3A | 0xA9 | 0xBC => Some(2),
        0x11
        | 0x13
        | 0x14
        | 0x84
        | 0x99..=0xA8
        | 0xB2..=0xB8
        | 0xBB
        | 0xBD
        | 0xC0
        | 0xC1
        | 0xC6
        | 0xC7 => Some(3),
        0xC5 => Some(4),
        0xB9 | 0xBA | 0xC8 | 0xC9 => Some(5),
        0xAA => switch_table_length(code, pc, true),
        0xAB => switch_table_length(code, pc, false),
        0xC4 => {
            if code.get(pc + 1)? == &0x84 {
                Some(6)
            } else {
                Some(4)
            }
        }
        _ => Some(1),
    }
}

fn switch_table_length(code: &[u8], pc: usize, table: bool) -> Option<usize> {
    let aligned = (pc + 1).div_ceil(4) * 4;
    let default = read_u32(code, aligned)?;
    let _ = default;
    let count = if table {
        let low = read_u32(code, aligned.checked_add(4)?)?;
        let high = read_u32(code, aligned.checked_add(8)?)?;
        usize::try_from(high.checked_sub(low)?.checked_add(1)?)
            .ok()?
            .min(1_000_000)
    } else {
        usize::try_from(read_u32(code, aligned.checked_add(4)?)?)
            .ok()?
            .min(1_000_000)
    };
    let fixed = if table { 12 } else { 8 };
    let end = aligned
        .checked_add(fixed)?
        .checked_add(count.checked_mul(4)?)?;
    end.checked_sub(pc)
}

fn read_u32(code: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        code.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn chacha20_stream(constants: &[u8], key: &[u8; 32], nonce: &[u8; 12], length: usize) -> Vec<u8> {
    let mut initial = [0_u32; 16];
    for (index, word) in initial.iter_mut().take(4).enumerate() {
        *word = u32::from_le_bytes(constants[index * 4..index * 4 + 4].try_into().unwrap());
    }
    for (index, word) in initial.iter_mut().skip(4).take(8).enumerate() {
        *word = u32::from_le_bytes(key[index * 4..index * 4 + 4].try_into().unwrap());
    }
    initial[13] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
    initial[14] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
    initial[15] = u32::from_le_bytes(nonce[8..12].try_into().unwrap());

    let mut output = Vec::with_capacity(length);
    while output.len() < length {
        let mut working = initial;
        for _ in 0..10 {
            quarter_round(&mut working, 0, 4, 8, 12);
            quarter_round(&mut working, 1, 5, 9, 13);
            quarter_round(&mut working, 2, 6, 10, 14);
            quarter_round(&mut working, 3, 7, 11, 15);
            quarter_round(&mut working, 0, 5, 10, 15);
            quarter_round(&mut working, 1, 6, 11, 12);
            quarter_round(&mut working, 2, 7, 8, 13);
            quarter_round(&mut working, 3, 4, 9, 14);
        }
        let mut block = [0_u8; 64];
        for (index, word) in working.iter().enumerate() {
            let sum = word.wrapping_add(initial[index]);
            block[index * 4..index * 4 + 4].copy_from_slice(&sum.to_le_bytes());
        }
        let amount = (length - output.len()).min(64);
        output.extend_from_slice(&block[..amount]);
        initial[12] = initial[12].wrapping_add(1);
        if initial[12] == 0 {
            initial[13] = initial[13].wrapping_add(1);
        }
    }
    output
}

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha_stream_is_deterministic() {
        let first = chacha20_stream(&[7; 16], &[9; 32], &[1; 12], 96);
        let second = chacha20_stream(&[7; 16], &[9; 32], &[1; 12], 96);
        assert_eq!(first, second);
        assert_eq!(first.len(), 96);
    }

    #[test]
    fn decodes_known_jnic_keystream() {
        let const_bytes = b" jnic.dev v3.5.1";
        let key_bytes: [u8; 32] = [
            0xe2, 0xd6, 0x6e, 0x99, 0x56, 0xe3, 0x4a, 0xb2, 0x4b, 0x4b, 0x9c, 0x6f, 0x1d, 0x76,
            0x0d, 0x34, 0x37, 0x8a, 0x94, 0x5a, 0xcd, 0xdf, 0x1e, 0xca, 0xc9, 0x54, 0xbc, 0x57,
            0xdc, 0x3f, 0xbc, 0x57,
        ];
        let nonce_bytes: [u8; 12] = [
            0xab, 0xed, 0x77, 0xfb, 0x50, 0xea, 0x03, 0x1a, 0x50, 0xd9, 0x65, 0x33,
        ];
        let ks = chacha20_stream(const_bytes, &key_bytes, &nonce_bytes, 10449);
        let rdata_0 = [
            0xaa, 0x4a, 0xdf, 0xf0, 0x19, 0x26, 0x4a, 0x2c, 0x71, 0x1b, 0x0b, 0xf7, 0xa0, 0x03,
            0x94, 0x8c,
        ];
        let dec: Vec<u8> = rdata_0
            .iter()
            .zip(&ks[0x1dc0..0x1dd0])
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(&dec, b"java/lang/System");
    }

    #[test]
    fn end_to_end_loader_secrets_test() {
        use crate::archive::{JarArchive, decompress_raw_lzma2};
        use crate::classfile::parse_class;
        use crate::pe::find_embedded_pe64;
        use std::path::Path;

        let fixture = Path::new("../reference/JavaObfuscatorTest/sample/JNIC-3.5.1.jar");
        if !fixture.exists() {
            return;
        }
        let archive = JarArchive::open_default(fixture).unwrap();
        let mut classes = Vec::new();
        for entry in archive.entries() {
            if entry.name.ends_with(".class") {
                let bytes = archive.read(&entry.name).unwrap();
                if let Ok(class) = parse_class(&bytes, entry.name.clone()) {
                    classes.push(class);
                }
            }
        }
        let dat_name = archive
            .entries()
            .iter()
            .find(|e| e.name.ends_with(".dat"))
            .unwrap()
            .name
            .clone();
        let compressed = archive.read(&dat_name).unwrap();
        let decompressed = decompress_raw_lzma2(&compressed, 1024 * 1024 * 1024).unwrap();
        let (_, pe_bytes) = find_embedded_pe64(&decompressed).unwrap();
        let pe = PeImage::parse(pe_bytes).unwrap();
        let (key, constants) = recover_chacha_key_and_constants(&pe).unwrap();
        let nonce = loader_nonce(&classes).unwrap();
        let loader = classes
            .iter()
            .find(|class| {
                !class.dat_resources.is_empty()
                    && class.methods.iter().any(|method| method.name == "<clinit>")
            })
            .unwrap();
        let clinit = loader
            .methods
            .iter()
            .find(|m| m.name == "<clinit>")
            .unwrap();
        let vals = all_put_int_values(loader, clinit);
        println!("all putInt values (count {}): {:x?}", vals.len(), vals);
        println!("recovered key: {:02x?}", key);
        println!(
            "recovered constants: {:?}",
            String::from_utf8_lossy(&constants)
        );
        println!("recovered nonce: {:02x?}", nonce);
        let secrets = recover_loader_secrets(&pe, &classes).unwrap();
        assert_eq!(secrets.global_rva, 0x2a048);
        let rdata_0 = [
            0xaa, 0x4a, 0xdf, 0xf0, 0x19, 0x26, 0x4a, 0x2c, 0x71, 0x1b, 0x0b, 0xf7, 0xa0, 0x03,
            0x94, 0x8c,
        ];
        let dec: Vec<u8> = rdata_0
            .iter()
            .zip(&secrets.keystream[0x1dc0..0x1dd0])
            .map(|(a, b)| a ^ b)
            .collect();
        assert_eq!(&dec, b"java/lang/System");
    }
}

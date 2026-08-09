use std::collections::{BTreeMap, HashSet};

use anyhow::{Context, Result, bail, ensure};

use crate::limits::{MAX_PE_STRING_BYTES, MAX_PE_TABLE_ENTRIES};

const DOS_MAGIC: u16 = 0x5A4D;
const PE_SIGNATURE: u32 = 0x0000_4550;
const AMD64_MACHINE: u16 = 0x8664;
const PE32_PLUS_MAGIC: u16 = 0x020B;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

#[derive(Debug, Clone)]
pub struct PeSection {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
    pub characteristics: u32,
}

impl PeSection {
    #[must_use]
    pub const fn executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }
}

#[derive(Debug, Clone)]
pub struct PeExport {
    pub name: String,
    pub rva: u32,
    pub forwarded: bool,
}

#[derive(Debug, Clone)]
pub struct PeImport {
    pub module: String,
    pub name: String,
    pub ordinal: Option<u16>,
    pub iat_rva: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFunction {
    pub begin: u32,
    pub end: u32,
    pub unwind: u32,
}

#[derive(Debug, Clone, Copy, Default)]
struct DataDirectory {
    rva: u32,
    size: u32,
}

#[derive(Debug, Clone)]
pub struct PeImage {
    bytes: Vec<u8>,
    pub image_base: u64,
    pub entry_point: u32,
    pub image_size: u32,
    pub timestamp: u32,
    headers_size: u32,
    directories: Vec<DataDirectory>,
    pub sections: Vec<PeSection>,
    pub exports: Vec<PeExport>,
    pub imports: Vec<PeImport>,
    pub functions: Vec<RuntimeFunction>,
    function_index: BTreeMap<u32, usize>,
}

impl PeImage {
    pub fn parse(bytes: Vec<u8>) -> Result<Self> {
        ensure!(bytes.len() >= 0x40, "PE DOS header is truncated");
        ensure!(read_u16(&bytes, 0)? == DOS_MAGIC, "PE MZ header is missing");
        let nt = usize::try_from(read_u32(&bytes, 0x3C)?)?;
        ensure!(
            read_u32(&bytes, nt)? == PE_SIGNATURE,
            "PE signature is missing"
        );
        ensure!(
            read_u16(&bytes, nt + 4)? == AMD64_MACHINE,
            "only Windows x86-64 PE payloads are supported"
        );
        let section_count = usize::from(read_u16(&bytes, nt + 6)?);
        let timestamp = read_u32(&bytes, nt + 8)?;
        let optional_size = usize::from(read_u16(&bytes, nt + 20)?);
        let optional = checked_add(nt, 24)?;
        range(&bytes, optional, optional_size, "PE optional header")?;
        ensure!(optional_size >= 112, "PE optional header is too small");
        ensure!(
            read_u16(&bytes, optional)? == PE32_PLUS_MAGIC,
            "PE32+ optional header is required"
        );
        let entry_point = read_u32(&bytes, optional + 16)?;
        let image_base = read_u64(&bytes, optional + 24)?;
        let image_size = read_u32(&bytes, optional + 56)?;
        let headers_size = read_u32(&bytes, optional + 60)?;
        let directory_count = usize::try_from(read_u32(&bytes, optional + 108)?)?;
        let available_directories = (optional_size - 112) / 8;
        let directory_count = directory_count.min(available_directories);
        let mut directories = Vec::with_capacity(directory_count);
        for index in 0..directory_count {
            let offset = optional + 112 + index * 8;
            directories.push(DataDirectory {
                rva: read_u32(&bytes, offset)?,
                size: read_u32(&bytes, offset + 4)?,
            });
        }

        let section_table = checked_add(optional, optional_size)?;
        let table_size = section_count
            .checked_mul(40)
            .context("PE section-table size overflow")?;
        range(&bytes, section_table, table_size, "PE section table")?;
        let mut sections = Vec::with_capacity(section_count);
        for index in 0..section_count {
            let offset = section_table + index * 40;
            let raw_name = &bytes[offset..offset + 8];
            let name_end = raw_name.iter().position(|byte| *byte == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&raw_name[..name_end]).into_owned();
            let section = PeSection {
                name,
                virtual_size: read_u32(&bytes, offset + 8)?,
                virtual_address: read_u32(&bytes, offset + 12)?,
                raw_size: read_u32(&bytes, offset + 16)?,
                raw_offset: read_u32(&bytes, offset + 20)?,
                characteristics: read_u32(&bytes, offset + 36)?,
            };
            if section.raw_size != 0 {
                range(
                    &bytes,
                    usize::try_from(section.raw_offset)?,
                    usize::try_from(section.raw_size)?,
                    "PE section data",
                )?;
            }
            sections.push(section);
        }

        let mut image = Self {
            bytes,
            image_base,
            entry_point,
            image_size,
            timestamp,
            headers_size,
            directories,
            sections,
            exports: Vec::new(),
            imports: Vec::new(),
            functions: Vec::new(),
            function_index: BTreeMap::new(),
        };
        image.parse_exports()?;
        image.parse_imports()?;
        image.parse_runtime_functions()?;
        Ok(image)
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn section_for(&self, rva: u32) -> Option<&PeSection> {
        self.sections.iter().find(|section| {
            let span = u64::from(section.virtual_size.max(section.raw_size));
            rva >= section.virtual_address && u64::from(rva - section.virtual_address) < span
        })
    }

    #[must_use]
    pub fn executable_rva(&self, rva: u32) -> bool {
        self.section_for(rva).is_some_and(PeSection::executable)
    }

    #[must_use]
    pub fn file_offset(&self, rva: u32, length: usize) -> Option<usize> {
        if rva < self.headers_size {
            let offset = usize::try_from(rva).ok()?;
            return offset
                .checked_add(length)
                .filter(|end| *end <= self.bytes.len())
                .map(|_| offset);
        }
        let section = self.section_for(rva)?;
        let delta = rva.checked_sub(section.virtual_address)?;
        if delta > section.raw_size
            || u64::try_from(length).ok()? > u64::from(section.raw_size - delta)
        {
            return None;
        }
        let offset = u64::from(section.raw_offset) + u64::from(delta);
        let offset = usize::try_from(offset).ok()?;
        offset
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .map(|_| offset)
    }

    pub fn slice(&self, rva: u32, length: usize) -> Result<&[u8]> {
        let offset = self
            .file_offset(rva, length)
            .with_context(|| format!("PE RVA 0x{rva:x} is not backed by file data"))?;
        Ok(&self.bytes[offset..offset + length])
    }

    #[must_use]
    pub fn function_at(&self, begin: u32) -> Option<RuntimeFunction> {
        self.function_index
            .get(&begin)
            .and_then(|index| self.functions.get(*index))
            .copied()
    }

    #[must_use]
    pub fn next_function(&self, rva: u32) -> Option<RuntimeFunction> {
        self.function_index
            .range((std::ops::Bound::Excluded(rva), std::ops::Bound::Unbounded))
            .next()
            .and_then(|(_, index)| self.functions.get(*index))
            .copied()
    }

    pub fn read_u32_rva(&self, rva: u32) -> Result<u32> {
        let offset = self.file_offset(rva, 4).context("invalid PE u32 RVA")?;
        read_u32(&self.bytes, offset)
    }

    pub fn read_u64_rva(&self, rva: u32) -> Result<u64> {
        let offset = self.file_offset(rva, 8).context("invalid PE u64 RVA")?;
        read_u64(&self.bytes, offset)
    }

    fn read_u16_rva(&self, rva: u32) -> Result<u16> {
        let offset = self.file_offset(rva, 2).context("invalid PE u16 RVA")?;
        read_u16(&self.bytes, offset)
    }

    fn cstring(&self, rva: u32) -> Result<String> {
        let mut output = Vec::new();
        for index in 0..MAX_PE_STRING_BYTES {
            let current = rva
                .checked_add(u32::try_from(index)?)
                .context("PE string RVA overflow")?;
            let offset = self
                .file_offset(current, 1)
                .context("unterminated PE string")?;
            let byte = self.bytes[offset];
            if byte == 0 {
                return Ok(String::from_utf8_lossy(&output).into_owned());
            }
            output.push(byte);
        }
        bail!("PE string exceeds the safety limit at RVA 0x{rva:x}")
    }

    fn directory(&self, index: usize) -> DataDirectory {
        self.directories.get(index).copied().unwrap_or_default()
    }

    fn parse_exports(&mut self) -> Result<()> {
        let directory = self.directory(0);
        if directory.rva == 0 || directory.size == 0 {
            return Ok(());
        }
        let offset = self
            .file_offset(directory.rva, 40)
            .context("invalid PE export directory")?;
        let function_count = usize::try_from(read_u32(&self.bytes, offset + 20)?)?;
        let name_count = usize::try_from(read_u32(&self.bytes, offset + 24)?)?;
        ensure!(
            function_count <= MAX_PE_TABLE_ENTRIES && name_count <= MAX_PE_TABLE_ENTRIES,
            "excessive PE export count"
        );
        let functions_rva = read_u32(&self.bytes, offset + 28)?;
        let names_rva = read_u32(&self.bytes, offset + 32)?;
        let ordinals_rva = read_u32(&self.bytes, offset + 36)?;
        for index in 0..name_count {
            let index_u32 = u32::try_from(index)?;
            let name_rva = self.read_u32_rva(
                names_rva
                    .checked_add(index_u32.saturating_mul(4))
                    .context("export-name table overflow")?,
            )?;
            let ordinal = usize::from(
                self.read_u16_rva(
                    ordinals_rva
                        .checked_add(index_u32.saturating_mul(2))
                        .context("export-ordinal table overflow")?,
                )?,
            );
            ensure!(ordinal < function_count, "invalid PE export ordinal");
            let function_rva = self.read_u32_rva(
                functions_rva
                    .checked_add(u32::try_from(ordinal)?.saturating_mul(4))
                    .context("export-function table overflow")?,
            )?;
            let forwarded = function_rva >= directory.rva
                && u64::from(function_rva) < u64::from(directory.rva) + u64::from(directory.size);
            self.exports.push(PeExport {
                name: self.cstring(name_rva)?,
                rva: function_rva,
                forwarded,
            });
        }
        Ok(())
    }

    fn parse_imports(&mut self) -> Result<()> {
        let directory = self.directory(1);
        if directory.rva == 0 || directory.size == 0 {
            return Ok(());
        }
        for descriptor_index in 0..MAX_PE_TABLE_ENTRIES.min(65_536) {
            let delta = u32::try_from(descriptor_index)?.saturating_mul(20);
            let descriptor_rva = directory
                .rva
                .checked_add(delta)
                .context("import directory overflow")?;
            let offset = self
                .file_offset(descriptor_rva, 20)
                .context("invalid PE import descriptor")?;
            let original_thunk = read_u32(&self.bytes, offset)?;
            let module_rva = read_u32(&self.bytes, offset + 12)?;
            let first_thunk = read_u32(&self.bytes, offset + 16)?;
            if original_thunk == 0 && module_rva == 0 && first_thunk == 0 {
                return Ok(());
            }
            let module = self.cstring(module_rva)?;
            let thunk_rva = if original_thunk == 0 {
                first_thunk
            } else {
                original_thunk
            };
            for thunk_index in 0..MAX_PE_TABLE_ENTRIES {
                let delta = u32::try_from(thunk_index)?.saturating_mul(8);
                let value = self.read_u64_rva(
                    thunk_rva
                        .checked_add(delta)
                        .context("import thunk overflow")?,
                )?;
                if value == 0 {
                    break;
                }
                let (name, ordinal) = if value & (1_u64 << 63) != 0 {
                    let ordinal = (value & 0xFFFF) as u16;
                    (format!("ordinal_{ordinal}"), Some(ordinal))
                } else {
                    let hint_name =
                        u32::try_from(value).context("PE32+ import name RVA exceeds 32 bits")?;
                    (
                        self.cstring(hint_name.checked_add(2).context("import name overflow")?)?,
                        None,
                    )
                };
                self.imports.push(PeImport {
                    module: module.clone(),
                    name,
                    ordinal,
                    iat_rva: first_thunk.checked_add(delta).context("IAT RVA overflow")?,
                });
            }
        }
        bail!("unterminated PE import directory")
    }

    fn parse_runtime_functions(&mut self) -> Result<()> {
        let directory = self.directory(3);
        if directory.rva == 0 || directory.size == 0 {
            return Ok(());
        }
        ensure!(directory.size % 12 == 0, "invalid PE exception directory");
        let count = usize::try_from(directory.size / 12)?;
        ensure!(
            count <= MAX_PE_TABLE_ENTRIES,
            "excessive PE runtime-function count"
        );
        for index in 0..count {
            let offset = u32::try_from(index)?.saturating_mul(12);
            let base = directory
                .rva
                .checked_add(offset)
                .context("runtime-function table overflow")?;
            let function = RuntimeFunction {
                begin: self.read_u32_rva(base)?,
                end: self.read_u32_rva(base + 4)?,
                unwind: self.read_u32_rva(base + 8)?,
            };
            if function.begin < function.end && function.end <= self.image_size {
                self.functions.push(function);
            }
        }
        self.functions
            .sort_unstable_by_key(|function| function.begin);
        self.function_index = self
            .functions
            .iter()
            .enumerate()
            .map(|(index, function)| (function.begin, index))
            .collect();
        Ok(())
    }
}

pub fn find_embedded_pe64(stream: &[u8]) -> Result<(usize, Vec<u8>)> {
    for offset in 0..stream.len().saturating_sub(1) {
        if stream[offset] != b'M' || stream[offset + 1] != b'Z' {
            continue;
        }
        let Some(size) = embedded_image_size(stream, offset) else {
            continue;
        };
        let end = offset
            .checked_add(size)
            .context("embedded PE size overflow")?;
        if end > stream.len() {
            continue;
        }
        let candidate = stream[offset..end].to_vec();
        if PeImage::parse(candidate.clone()).is_ok() {
            return Ok((offset, candidate));
        }
    }
    bail!("no Windows x86-64 PE payload was found in the decoded resource")
}

fn embedded_image_size(stream: &[u8], base: usize) -> Option<usize> {
    range(stream, base, 0x40, "embedded DOS header").ok()?;
    if read_u16(stream, base).ok()? != DOS_MAGIC {
        return None;
    }
    let nt = base.checked_add(usize::try_from(read_u32(stream, base + 0x3C).ok()?).ok()?)?;
    if read_u32(stream, nt).ok()? != PE_SIGNATURE || read_u16(stream, nt + 4).ok()? != AMD64_MACHINE
    {
        return None;
    }
    let section_count = usize::from(read_u16(stream, nt + 6).ok()?);
    let optional_size = usize::from(read_u16(stream, nt + 20).ok()?);
    if read_u16(stream, nt + 24).ok()? != PE32_PLUS_MAGIC {
        return None;
    }
    let optional = nt.checked_add(24)?;
    let table = optional.checked_add(optional_size)?;
    range(
        stream,
        table,
        section_count.checked_mul(40)?,
        "embedded section table",
    )
    .ok()?;
    let headers = usize::try_from(read_u32(stream, optional + 60).ok()?).ok()?;
    let mut end = headers;
    for index in 0..section_count {
        let section = table + index * 40;
        let raw_size = usize::try_from(read_u32(stream, section + 16).ok()?).ok()?;
        let raw_offset = usize::try_from(read_u32(stream, section + 20).ok()?).ok()?;
        end = end.max(raw_offset.checked_add(raw_size)?);
    }
    range(stream, base, end, "embedded image").ok()?;
    Some(end)
}

pub fn decode_jni_export_class(export_name: &str) -> Option<String> {
    let mut encoded = export_name.strip_prefix("Java_")?.to_owned();
    const SUFFIXES: [&str; 4] = [
        "__00024jnicLoader",
        "_00024jnicLoader",
        "__jnicLoader",
        "_jnicLoader",
    ];
    let suffix = SUFFIXES.iter().find(|suffix| encoded.ends_with(**suffix))?;
    encoded.truncate(encoded.len() - suffix.len());

    let bytes = encoded.as_bytes();
    let mut output = String::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'_' {
            output.push(char::from(bytes[index]));
            index += 1;
            continue;
        }
        match bytes.get(index + 1).copied() {
            Some(b'1') => {
                output.push('_');
                index += 2;
            }
            Some(b'2') => {
                output.push(';');
                index += 2;
            }
            Some(b'3') => {
                output.push('[');
                index += 2;
            }
            Some(b'0') if index + 6 <= bytes.len() => {
                let digits = std::str::from_utf8(&bytes[index + 2..index + 6]).ok()?;
                let value = u16::from_str_radix(digits, 16).ok()?;
                output.push(char::from_u32(u32::from(value))?);
                index += 6;
            }
            _ => {
                output.push('/');
                index += 1;
            }
        }
    }
    Some(output)
}

pub fn scan_registration_targets(
    image: &PeImage,
    loader: RuntimeFunction,
    excluded_exports: &HashSet<u32>,
) -> Result<Vec<u32>> {
    let length = usize::try_from(loader.end - loader.begin)?;
    let code = image.slice(loader.begin, length)?;
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    for index in 0..code.len().saturating_sub(6) {
        let rex = code[index];
        if rex & 0xF8 != 0x48 || rex & 0x08 == 0 || code[index + 1] != 0x8D {
            continue;
        }
        let mod_rm = code[index + 2];
        if mod_rm & 0xC7 != 0x05 {
            continue;
        }
        let displacement = i32::from_le_bytes(code[index + 3..index + 7].try_into()?);
        let target = i64::from(loader.begin) + i64::try_from(index)? + 7 + i64::from(displacement);
        let Ok(target) = u32::try_from(target) else {
            continue;
        };
        if image.executable_rva(target)
            && !excluded_exports.contains(&target)
            && seen.insert(target)
        {
            targets.push(target);
        }
    }
    Ok(targets)
}

fn checked_add(left: usize, right: usize) -> Result<usize> {
    left.checked_add(right).context("file offset overflow")
}

fn range<'a>(bytes: &'a [u8], offset: usize, length: usize, what: &str) -> Result<&'a [u8]> {
    let end = offset.checked_add(length).context("file range overflow")?;
    bytes
        .get(offset..end)
        .with_context(|| format!("truncated {what}"))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        range(bytes, offset, 2, "u16")?.try_into()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        range(bytes, offset, 4, "u32")?.try_into()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        range(bytes, offset, 8, "u64")?.try_into()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_loader_export() {
        assert_eq!(
            decode_jni_export_class("Java_example_nativebridge_Entry__00024jnicLoader"),
            Some("example/nativebridge/Entry".to_owned())
        );
    }

    #[test]
    fn rejects_non_loader_export() {
        assert_eq!(decode_jni_export_class("JNI_OnLoad"), None);
    }
}

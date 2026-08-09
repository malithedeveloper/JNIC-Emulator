use std::fs::File;
use std::io::{BufReader, Cursor, Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use zip::ZipArchive;

use crate::limits::{DEFAULT_MAX_ENTRY_BYTES, DEFAULT_MAX_INPUT_BYTES};

#[derive(Debug, Clone)]
pub struct ArchiveEntry {
    pub name: String,
    pub uncompressed_size: u64,
}

#[derive(Debug, Clone)]
pub struct JarArchive {
    bytes: Vec<u8>,
    entries: Vec<ArchiveEntry>,
    max_entry_bytes: u64,
}

impl JarArchive {
    pub fn open(path: &Path, max_input_bytes: u64, max_entry_bytes: u64) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("cannot open input {}", path.display()))?;
        let size = file.metadata()?.len();
        ensure!(
            size <= max_input_bytes,
            "input is {size} bytes and exceeds the {max_input_bytes}-byte safety limit"
        );
        let capacity = usize::try_from(size).context("input is too large for this platform")?;
        let mut bytes = Vec::with_capacity(capacity);
        BufReader::new(file).read_to_end(&mut bytes)?;

        let mut archive =
            ZipArchive::new(Cursor::new(&bytes)).context("invalid ZIP/JAR archive")?;
        let mut entries = Vec::with_capacity(archive.len());
        for index in 0..archive.len() {
            let file = archive.by_index(index)?;
            if !file.is_file() {
                continue;
            }
            let name = file.name().replace('\\', "/");
            if name.starts_with('/') || name.split('/').any(|part| part == "..") {
                bail!("unsafe ZIP member name: {name}");
            }
            ensure!(
                file.size() <= max_entry_bytes,
                "ZIP member {name} exceeds the {max_entry_bytes}-byte safety limit"
            );
            entries.push(ArchiveEntry {
                name,
                uncompressed_size: file.size(),
            });
        }
        drop(archive);

        Ok(Self {
            bytes,
            entries,
            max_entry_bytes,
        })
    }

    pub fn open_default(path: &Path) -> Result<Self> {
        Self::open(path, DEFAULT_MAX_INPUT_BYTES, DEFAULT_MAX_ENTRY_BYTES)
    }

    #[must_use]
    pub fn entries(&self) -> &[ArchiveEntry] {
        &self.entries
    }

    pub fn read(&self, name: &str) -> Result<Vec<u8>> {
        let mut archive = ZipArchive::new(Cursor::new(&self.bytes))?;
        let mut file = archive
            .by_name(name)
            .with_context(|| format!("JAR member is absent: {name}"))?;
        ensure!(!file.is_dir(), "JAR member is a directory: {name}");
        ensure!(
            file.size() <= self.max_entry_bytes,
            "JAR member {name} exceeds the configured safety limit"
        );
        let capacity = usize::try_from(file.size()).context("JAR member is too large")?;
        let mut output = Vec::with_capacity(capacity);
        let mut limited = (&mut file).take(self.max_entry_bytes.saturating_add(1));
        limited.read_to_end(&mut output)?;
        ensure!(
            u64::try_from(output.len())? <= self.max_entry_bytes,
            "JAR member expanded beyond the configured safety limit: {name}"
        );
        Ok(output)
    }
}

pub fn decompress_raw_lzma2(input: &[u8], max_output_bytes: u64) -> Result<Vec<u8>> {
    let mut reader = Cursor::new(input);
    let mut writer = LimitedWriter::new(max_output_bytes);
    lzma_rs::lzma2_decompress(&mut reader, &mut writer)
        .map_err(|error| anyhow::anyhow!("invalid raw LZMA2 stream: {error}"))?;
    Ok(writer.into_inner())
}

struct LimitedWriter {
    bytes: Vec<u8>,
    limit: u64,
}

impl LimitedWriter {
    fn new(limit: u64) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for LimitedWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let next = u64::try_from(self.bytes.len())
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(buffer.len()).unwrap_or(u64::MAX));
        if next > self.limit {
            return Err(std::io::Error::other(format!(
                "decoded stream exceeds the {}-byte safety limit",
                self.limit
            )));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    #[test]
    fn limited_writer_enforces_bound() {
        let mut writer = LimitedWriter::new(3);
        assert_eq!(writer.write(b"abc").unwrap(), 3);
        assert!(writer.write(b"d").is_err());
    }
}

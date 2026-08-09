use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};

use crate::archive::{JarArchive, decompress_raw_lzma2};
use crate::classfile::{JavaClass, JavaMethod, parse_class};
use crate::emulator::{NativeAnalysis, TraceConfig, analyze_native};
use crate::limits::{DEFAULT_MAX_ENTRY_BYTES, DEFAULT_MAX_INPUT_BYTES};
use crate::pe::{
    PeImage, RuntimeFunction, decode_jni_export_class, find_embedded_pe64,
    scan_registration_targets,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    Jar,
    Pe,
}

#[derive(Debug, Clone, Copy)]
pub struct AnalysisConfig {
    pub max_input_bytes: u64,
    pub max_entry_bytes: u64,
    pub max_decoded_resource_bytes: u64,
    pub trace: TraceConfig,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_entry_bytes: DEFAULT_MAX_ENTRY_BYTES,
            max_decoded_resource_bytes: DEFAULT_MAX_INPUT_BYTES,
            trace: TraceConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MappedMethod {
    pub method: JavaMethod,
    pub native_rva: Option<u32>,
    pub function: Option<RuntimeFunction>,
    pub analysis: NativeAnalysis,
}

#[derive(Debug, Clone)]
pub struct ClassMapping {
    pub internal_name: String,
    pub export_name: String,
    pub loader_rva: u32,
    pub discovered_targets: usize,
    pub methods: Vec<MappedMethod>,
}

#[derive(Debug, Clone)]
pub struct AnalysisModel {
    pub input_path: PathBuf,
    pub input_kind: InputKind,
    pub input_size: u64,
    pub input_sha256: String,
    pub loader_entry: Option<String>,
    pub native_resource: Option<String>,
    pub compressed_resource_size: usize,
    pub decoded_resource_size: usize,
    pub payload_offset: usize,
    pub pe_size: usize,
    pub pe: PeImage,
    pub classes_parsed: usize,
    pub mappings: Vec<ClassMapping>,
    pub warnings: Vec<String>,
}

pub fn analyze_path(path: &Path, config: AnalysisConfig) -> Result<AnalysisModel> {
    ensure!(
        config.max_input_bytes > 0,
        "maximum input size must be nonzero"
    );
    ensure!(
        config.max_entry_bytes > 0,
        "maximum entry size must be nonzero"
    );
    ensure!(
        config.max_decoded_resource_bytes > 0,
        "maximum decoded-resource size must be nonzero"
    );
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if extension.eq_ignore_ascii_case("jar") || extension.eq_ignore_ascii_case("zip") {
        inspect_jar(path, config)
    } else {
        inspect_pe(path, config)
    }
}

fn inspect_jar(path: &Path, config: AnalysisConfig) -> Result<AnalysisModel> {
    let (input_size, input_sha256) = file_identity(path, config.max_input_bytes)?;
    let archive = JarArchive::open(path, config.max_input_bytes, config.max_entry_bytes)?;
    let entry_names = archive
        .entries()
        .iter()
        .map(|entry| entry.name.as_str())
        .collect::<HashSet<_>>();
    let dat_entries = archive
        .entries()
        .iter()
        .filter(|entry| entry.name.to_ascii_lowercase().ends_with(".dat"))
        .map(|entry| entry.name.clone())
        .collect::<Vec<_>>();

    let mut classes = Vec::new();
    let mut warnings = Vec::new();
    for entry in archive
        .entries()
        .iter()
        .filter(|entry| entry.name.to_ascii_lowercase().ends_with(".class"))
    {
        match archive
            .read(&entry.name)
            .and_then(|bytes| parse_class(&bytes, entry.name.clone()))
        {
            Ok(class) => classes.push(class),
            Err(error) => warnings.push(format!("class parse skipped: {} ({error:#})", entry.name)),
        }
    }
    ensure!(
        !classes.is_empty(),
        "JAR does not contain a parseable class file"
    );

    let mut exact_pairs = Vec::new();
    for (class_index, class) in classes.iter().enumerate() {
        for resource in &class.dat_resources {
            let normalized = normalize_resource_name(resource);
            if entry_names.contains(normalized.as_str()) {
                exact_pairs.push((class_index, normalized));
            }
        }
    }
    exact_pairs.sort();
    exact_pairs.dedup();
    let selected = if exact_pairs.len() == 1 {
        exact_pairs.pop()
    } else {
        let loader_pairs = exact_pairs
            .iter()
            .filter(|(index, _)| classes[*index].has_loader_method())
            .cloned()
            .collect::<Vec<_>>();
        if loader_pairs.len() == 1 {
            loader_pairs.into_iter().next()
        } else {
            let candidates = classes
                .iter()
                .enumerate()
                .filter(|(_, class)| {
                    class.has_loader_method() || class.internal_name.ends_with("/JNICLoader")
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            if candidates.len() == 1 && dat_entries.len() == 1 {
                Some((candidates[0], dat_entries[0].clone()))
            } else {
                None
            }
        }
    };
    let Some((loader_index, resource_name)) = selected else {
        bail!("no unambiguous loader class and .dat resource pair was found");
    };
    let loader_entry = classes[loader_index].entry_name.clone();
    let compressed = archive.read(&resource_name)?;
    let compressed_resource_size = compressed.len();
    let decoded = decompress_raw_lzma2(&compressed, config.max_decoded_resource_bytes)?;
    let decoded_resource_size = decoded.len();
    let (payload_offset, pe_bytes) = find_embedded_pe64(&decoded)?;
    let pe_size = pe_bytes.len();
    let pe = PeImage::parse(pe_bytes)?;

    let mappings = build_mappings(&classes, &pe, config.trace, &mut warnings)?;
    let mapped_names = mappings
        .iter()
        .map(|mapping| mapping.internal_name.as_str())
        .collect::<HashSet<_>>();
    for class in &classes {
        if class.has_loader_method()
            && !class.protected_methods().is_empty()
            && !mapped_names.contains(class.internal_name.as_str())
        {
            warnings.push(format!(
                "protected class was not mapped to a loader export: {}",
                class.internal_name.replace('/', ".")
            ));
        }
    }

    Ok(AnalysisModel {
        input_path: path.to_path_buf(),
        input_kind: InputKind::Jar,
        input_size,
        input_sha256,
        loader_entry: Some(loader_entry),
        native_resource: Some(resource_name),
        compressed_resource_size,
        decoded_resource_size,
        payload_offset,
        pe_size,
        pe,
        classes_parsed: classes.len(),
        mappings,
        warnings,
    })
}

fn inspect_pe(path: &Path, config: AnalysisConfig) -> Result<AnalysisModel> {
    let (input_size, input_sha256) = file_identity(path, config.max_input_bytes)?;
    let bytes = read_bounded(path, config.max_input_bytes)?;
    let pe_size = bytes.len();
    let pe = PeImage::parse(bytes)?;
    Ok(AnalysisModel {
        input_path: path.to_path_buf(),
        input_kind: InputKind::Pe,
        input_size,
        input_sha256,
        loader_entry: None,
        native_resource: None,
        compressed_resource_size: 0,
        decoded_resource_size: 0,
        payload_offset: 0,
        pe_size,
        pe,
        classes_parsed: 0,
        mappings: Vec::new(),
        warnings: vec![
            "raw PE input has no Java class metadata; protected methods cannot be mapped"
                .to_owned(),
        ],
    })
}

fn build_mappings(
    classes: &[JavaClass],
    pe: &PeImage,
    trace: TraceConfig,
    warnings: &mut Vec<String>,
) -> Result<Vec<ClassMapping>> {
    let class_by_name = classes
        .iter()
        .map(|class| (class.internal_name.as_str(), class))
        .collect::<HashMap<_, _>>();
    let excluded_exports = pe
        .exports
        .iter()
        .map(|export| export.rva)
        .collect::<HashSet<_>>();
    let mut mapped_classes = HashSet::new();
    let mut mappings = Vec::new();

    for export in &pe.exports {
        if export.forwarded {
            continue;
        }
        let Some(class_name) = decode_jni_export_class(&export.name) else {
            continue;
        };
        if !mapped_classes.insert(class_name.clone()) {
            continue;
        }
        let Some(class) = class_by_name.get(class_name.as_str()).copied() else {
            warnings.push(format!(
                "loader export has no matching class: {}",
                export.name
            ));
            continue;
        };
        let protected = class.protected_methods();
        if protected.is_empty() {
            continue;
        }
        let Some(loader_function) = pe.function_at(export.rva) else {
            warnings.push(format!(
                "loader export lacks a runtime-function boundary: {}",
                export.name
            ));
            continue;
        };
        let targets = scan_registration_targets(pe, loader_function, &excluded_exports)?;
        let mut methods = Vec::with_capacity(protected.len());
        for (index, method) in protected.into_iter().enumerate() {
            let native_rva = targets.get(index).copied();
            let function = native_rva.and_then(|target| infer_function_boundary(pe, target));
            let analysis = if let Some(function) = function {
                match analyze_native(pe, function, trace) {
                    Ok(analysis) => analysis,
                    Err(error) => {
                        warnings.push(format!(
                            "native analysis skipped for {}.{}{}: {error:#}",
                            class.internal_name.replace('/', "."),
                            method.name,
                            method.descriptor
                        ));
                        NativeAnalysis::default()
                    }
                }
            } else {
                NativeAnalysis::default()
            };
            methods.push(MappedMethod {
                method: method.clone(),
                native_rva,
                function,
                analysis,
            });
        }
        if targets.len() != methods.len() {
            warnings.push(format!(
                "registration count mismatch for {}: {} native methods, {} targets",
                class.internal_name.replace('/', "."),
                methods.len(),
                targets.len()
            ));
        }
        mappings.push(ClassMapping {
            internal_name: class.internal_name.clone(),
            export_name: export.name.clone(),
            loader_rva: export.rva,
            discovered_targets: targets.len(),
            methods,
        });
    }
    mappings.sort_by(|left, right| left.internal_name.cmp(&right.internal_name));
    Ok(mappings)
}

fn infer_function_boundary(pe: &PeImage, target: u32) -> Option<RuntimeFunction> {
    if let Some(function) = pe.function_at(target) {
        return Some(function);
    }
    let section = pe.section_for(target)?;
    if !section.executable() {
        return None;
    }
    let section_end = section
        .virtual_address
        .checked_add(section.virtual_size.max(section.raw_size))?;
    let next = pe
        .next_function(target)
        .map_or(section_end, |function| function.begin.min(section_end));
    if next <= target || next - target > 1024 * 1024 {
        return None;
    }
    Some(RuntimeFunction {
        begin: target,
        end: next,
        unwind: 0,
    })
}

fn normalize_resource_name(value: &str) -> String {
    value.trim_start_matches('/').replace('\\', "/")
}

fn file_identity(path: &Path, limit: u64) -> Result<(u64, String)> {
    let file = File::open(path).with_context(|| format!("cannot open input {}", path.display()))?;
    let size = file.metadata()?.len();
    ensure!(
        size <= limit,
        "input is {size} bytes and exceeds the {limit}-byte safety limit"
    );
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok((size, format!("{:x}", hasher.finalize())))
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("cannot open input {}", path.display()))?;
    let size = file.metadata()?.len();
    ensure!(size <= limit, "input exceeds the configured safety limit");
    let mut reader = BufReader::new(file).take(limit.saturating_add(1));
    let mut bytes = Vec::with_capacity(usize::try_from(size)?);
    reader.read_to_end(&mut bytes)?;
    ensure!(
        u64::try_from(bytes.len())? <= limit,
        "input grew while being read"
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_resource_paths() {
        assert_eq!(
            normalize_resource_name("/native/payload.dat"),
            "native/payload.dat"
        );
        assert_eq!(
            normalize_resource_name("native\\payload.dat"),
            "native/payload.dat"
        );
    }
}

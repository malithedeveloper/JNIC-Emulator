use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::analyzer::{AnalysisModel, InputKind};
use crate::descriptor::dotted;
use crate::dynamic_model::AnalysisMode;

#[must_use]
pub fn render_report(model: &AnalysisModel) -> String {
    let declared_methods = model
        .mappings
        .iter()
        .map(|mapping| mapping.methods.len())
        .sum::<usize>();
    let mapped_methods = model
        .mappings
        .iter()
        .flat_map(|mapping| &mapping.methods)
        .filter(|method| method.native_rva.is_some())
        .count();
    let native = model
        .mappings
        .iter()
        .flat_map(|mapping| &mapping.methods)
        .map(|method| &method.analysis)
        .collect::<Vec<_>>();
    let instructions = native
        .iter()
        .map(|analysis| analysis.decoded_instructions)
        .sum::<usize>();
    let path_states = native
        .iter()
        .map(|analysis| analysis.explored_path_states)
        .sum::<usize>();
    let loops = native
        .iter()
        .map(|analysis| analysis.loops.len())
        .sum::<usize>();
    let jni_calls = native
        .iter()
        .map(|analysis| analysis.jni_calls.len())
        .sum::<usize>();
    let dynamic_attempted = model
        .mappings
        .iter()
        .flat_map(|mapping| &mapping.methods)
        .filter(|method| method.dynamic.attempted)
        .count();
    let dynamic_completed = model
        .mappings
        .iter()
        .flat_map(|mapping| &mapping.methods)
        .filter(|method| method.dynamic.completed)
        .count();

    let mut output = String::new();
    writeln!(
        output,
        "========================================================================"
    )
    .unwrap();
    writeln!(
        output,
        "  {}",
        if model.mode == AnalysisMode::Dynamic {
            "JNIC ISOLATED DYNAMIC ANALYSIS REPORT"
        } else {
            "JNIC CONTROLLED STATIC EMULATION REPORT"
        }
    )
    .unwrap();
    writeln!(
        output,
        "========================================================================"
    )
    .unwrap();
    writeln!(
        output,
        "  Safety Mode      : {}",
        if model.mode == AnalysisMode::Dynamic {
            "ISOLATED X86-64 CPU EMULATION"
        } else {
            "PARSE + BOUNDED SYMBOLIC INTERPRETATION"
        }
    )
    .unwrap();
    writeln!(
        output,
        "  Host Execution   : {}",
        if model.mode == AnalysisMode::Dynamic {
            "TARGET CODE EMULATED ONLY, NEVER HOST-CALLED"
        } else {
            "TARGET CODE NEVER LOADED OR INVOKED"
        }
    )
    .unwrap();
    writeln!(
        output,
        "  Input Type       : {}",
        match model.input_kind {
            InputKind::Jar => "JAR WITH EMBEDDED PE",
            InputKind::Pe => "RAW PE32+",
        }
    )
    .unwrap();
    writeln!(
        output,
        "  Input             : {}",
        model.input_path.display()
    )
    .unwrap();
    writeln!(
        output,
        "  Input Size        : {}",
        format_size(model.input_size)
    )
    .unwrap();
    writeln!(output, "  SHA-256           : {}", model.input_sha256).unwrap();
    if let Some(loader) = &model.loader_entry {
        writeln!(output, "  Loader Class      : {loader}").unwrap();
    }
    if let Some(resource) = &model.native_resource {
        writeln!(output, "  Native Resource   : {resource}").unwrap();
        writeln!(
            output,
            "  Resource Stream   : {} compressed, {} decoded",
            format_size(model.compressed_resource_size as u64),
            format_size(model.decoded_resource_size as u64)
        )
        .unwrap();
        writeln!(output, "  PE Stream Offset  : 0x{:x}", model.payload_offset).unwrap();
    }
    writeln!(
        output,
        "  PE Payload        : {}",
        format_size(model.pe_size as u64)
    )
    .unwrap();
    writeln!(output, "  PE Image Base     : 0x{:x}", model.pe.image_base).unwrap();
    writeln!(
        output,
        "  PE Entry Point    : RVA 0x{:x} (not called)",
        model.pe.entry_point
    )
    .unwrap();
    writeln!(output, "  Java Classes      : {}", model.classes_parsed).unwrap();
    writeln!(output, "  Protected Classes : {}", model.mappings.len()).unwrap();
    writeln!(output, "  Protected Methods : {declared_methods}").unwrap();
    writeln!(output, "  Methods Mapped    : {mapped_methods}").unwrap();
    writeln!(output, "  Decoded x86       : {instructions} instructions").unwrap();
    writeln!(output, "  Explored States   : {path_states}").unwrap();
    writeln!(output, "  Back-edge Loops   : {loops}").unwrap();
    writeln!(output, "  JNI Call Sites    : {jni_calls}").unwrap();
    if model.mode == AnalysisMode::Dynamic {
        writeln!(
            output,
            "  Dynamic Traces    : {dynamic_completed}/{dynamic_attempted} completed"
        )
        .unwrap();
    }
    writeln!(
        output,
        "========================================================================\n"
    )
    .unwrap();

    writeln!(output, "PE SECTIONS").unwrap();
    for section in &model.pe.sections {
        writeln!(
            output,
            "  {:<9} RVA {:>#10x}  virtual {:>10}  raw {:>10}{}",
            section.name,
            section.virtual_address,
            format_size(u64::from(section.virtual_size)),
            format_size(u64::from(section.raw_size)),
            if section.executable() {
                "  executable (decoded as data only)"
            } else {
                ""
            }
        )
        .unwrap();
    }

    writeln!(
        output,
        "\nPE IMPORTS (metadata only; no host import is resolved or called)"
    )
    .unwrap();
    if model.pe.imports.is_empty() {
        writeln!(output, "  none").unwrap();
    }
    for import in &model.pe.imports {
        writeln!(
            output,
            "  {}!{} @ IAT 0x{:x}",
            import.module, import.name, import.iat_rva
        )
        .unwrap();
    }

    for mapping in &model.mappings {
        writeln!(
            output,
            "\n========================================================================"
        )
        .unwrap();
        writeln!(output, "CLASS {}", dotted(&mapping.internal_name)).unwrap();
        writeln!(output, "  Loader export     : {}", mapping.export_name).unwrap();
        writeln!(output, "  Loader export RVA : 0x{:x}", mapping.loader_rva).unwrap();
        writeln!(output, "  Declared methods  : {}", mapping.methods.len()).unwrap();
        writeln!(
            output,
            "  Function targets  : {}",
            mapping.discovered_targets
        )
        .unwrap();
        writeln!(
            output,
            "========================================================================\n"
        )
        .unwrap();

        for method in &mapping.methods {
            let declaration = method
                .method
                .declaration()
                .unwrap_or_else(|_| format!("{}{}", method.method.name, method.method.descriptor));
            writeln!(output, "    {declaration}").unwrap();
            match method.native_rva {
                Some(rva) => writeln!(output, "      Native RVA       : 0x{rva:x}").unwrap(),
                None => writeln!(output, "      Native RVA       : unmapped").unwrap(),
            }
            let analysis = &method.analysis;
            writeln!(
                output,
                "      Control flow     : {} blocks, {} branches, {} loop back-edges",
                analysis.basic_blocks,
                analysis.conditional_branches,
                analysis.loops.len()
            )
            .unwrap();
            writeln!(
                output,
                "      Static emulation : {} instructions, {} path states{}",
                analysis.decoded_instructions,
                analysis.explored_path_states,
                if analysis.truncated {
                    " (limit reached)"
                } else {
                    ""
                }
            )
            .unwrap();
            if method.dynamic.attempted {
                writeln!(
                    output,
                    "      Dynamic trace    : {} scenarios, {} instructions, {}",
                    method.dynamic.scenarios,
                    method.dynamic.instructions,
                    if method.dynamic.completed {
                        "returned".to_owned()
                    } else {
                        method.dynamic.stop_reason.clone()
                    }
                )
                .unwrap();
                writeln!(output, "      Recovered Java:").unwrap();
                for event in method.dynamic.jni_events.iter().take(20) {
                    writeln!(output, "      event: {event}").unwrap();
                }
                let declaration = method
                    .method
                    .declaration()
                    .unwrap_or_else(|_| method.method.name.clone());
                writeln!(output, "      {declaration} {{").unwrap();
                for statement in &method.dynamic.java_body {
                    writeln!(output, "          {statement}").unwrap();
                }
                writeln!(output, "      }}").unwrap();
            }
            writeln!(
                output,
                "      Calls            : {} direct, {} indirect",
                analysis.direct_calls, analysis.indirect_calls
            )
            .unwrap();

            let mut jni_summary = BTreeMap::<&str, Vec<u32>>::new();
            for site in &analysis.jni_calls {
                jni_summary.entry(&site.name).or_default().push(site.rva);
            }
            if jni_summary.is_empty() {
                writeln!(output, "      JNI calls        : none recognized").unwrap();
            } else {
                writeln!(output, "      JNI calls:").unwrap();
                for (name, sites) in jni_summary {
                    let locations = sites
                        .iter()
                        .take(8)
                        .map(|rva| format!("0x{rva:x}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    writeln!(
                        output,
                        "        - {name}: {} site(s) [{}{}]",
                        sites.len(),
                        locations,
                        if sites.len() > 8 { ", ..." } else { "" }
                    )
                    .unwrap();
                }
            }
            writeln!(output).unwrap();
        }
    }

    writeln!(
        output,
        "========================================================================"
    )
    .unwrap();
    writeln!(output, "SUMMARY").unwrap();
    writeln!(output, "  Classes mapped    : {}", model.mappings.len()).unwrap();
    writeln!(output, "  Methods declared  : {declared_methods}").unwrap();
    writeln!(output, "  Methods mapped    : {mapped_methods}").unwrap();
    writeln!(
        output,
        "  Methods unmapped  : {}",
        declared_methods - mapped_methods
    )
    .unwrap();
    writeln!(output, "  Parse warnings    : {}", model.warnings.len()).unwrap();
    writeln!(output, "  Host instructions executed from target: 0").unwrap();
    writeln!(
        output,
        "========================================================================"
    )
    .unwrap();
    if !model.warnings.is_empty() {
        writeln!(output, "\nWARNINGS").unwrap();
        for warning in &model.warnings {
            writeln!(output, "  - {warning}").unwrap();
        }
    }
    output
}

#[must_use]
pub fn render_java_source(model: &AnalysisModel) -> String {
    let mut output = String::new();
    for mapping in &model.mappings {
        if let Some((package, _)) = mapping.internal_name.rsplit_once('/') {
            let _ = writeln!(output, "package {};\n", package.replace('/', "."));
        }
        let class_name = mapping
            .internal_name
            .rsplit('/')
            .next()
            .unwrap_or(mapping.internal_name.as_str())
            .to_owned();
        let _ = writeln!(output, "public class {class_name} {{");
        for method in &mapping.methods {
            if !method.dynamic.attempted {
                continue;
            }
            let declaration = method
                .method
                .declaration()
                .unwrap_or_else(|_| method.method.name.clone());
            let _ = writeln!(output, "    {declaration} {{");
            for statement in &method.dynamic.java_body {
                let _ = writeln!(output, "        {statement}");
            }
            let _ = writeln!(output, "    }}\n");
        }
        let _ = writeln!(output, "}}\n");
    }
    output
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} bytes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_sizes() {
        assert_eq!(format_size(12), "12 bytes");
        assert_eq!(format_size(1024), "1.00 KiB");
        assert_eq!(format_size(1024 * 1024), "1.00 MiB");
    }
}

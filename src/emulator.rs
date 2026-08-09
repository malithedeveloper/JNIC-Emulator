use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use anyhow::{Result, ensure};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};

use crate::jni::function_name;
use crate::pe::{PeImage, RuntimeFunction};

#[derive(Debug, Clone, Copy)]
pub struct TraceConfig {
    pub max_instructions_per_method: usize,
    pub max_path_states: usize,
    pub max_visits_per_block: usize,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            max_instructions_per_method: 250_000,
            max_path_states: 25_000,
            max_visits_per_block: 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JniCallSite {
    pub rva: u32,
    pub slot: usize,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LoopCandidate {
    pub header_rva: u32,
    pub back_edge_rva: u32,
}

#[derive(Debug, Clone, Default)]
pub struct NativeAnalysis {
    pub decoded_instructions: usize,
    pub basic_blocks: usize,
    pub conditional_branches: usize,
    pub direct_calls: usize,
    pub indirect_calls: usize,
    pub explored_path_states: usize,
    pub loops: Vec<LoopCandidate>,
    pub jni_calls: Vec<JniCallSite>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Symbol {
    EnvPointer,
    EnvTable,
}

/// Performs bounded control-flow interpretation without mapping or invoking target code.
pub fn analyze_native(
    image: &PeImage,
    function: RuntimeFunction,
    config: TraceConfig,
) -> Result<NativeAnalysis> {
    ensure!(function.begin < function.end, "empty native function");
    let length = usize::try_from(function.end - function.begin)?;
    let bytes = image.slice(function.begin, length)?;
    let start_ip = image.image_base + u64::from(function.begin);
    let end_ip = image.image_base + u64::from(function.end);
    let mut decoder = Decoder::with_ip(64, bytes, start_ip, DecoderOptions::NONE);
    let mut instructions = Vec::new();
    let mut truncated = false;
    while decoder.can_decode() {
        if instructions.len() >= config.max_instructions_per_method {
            truncated = true;
            break;
        }
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            break;
        }
        instructions.push(instruction);
    }

    let by_ip: HashMap<u64, usize> = instructions
        .iter()
        .enumerate()
        .map(|(index, instruction)| (instruction.ip(), index))
        .collect();
    let mut leaders = BTreeSet::from([start_ip]);
    let mut loops = HashSet::new();
    let mut conditional_branches = 0;
    let mut direct_calls = 0;
    let mut indirect_calls = 0;
    for instruction in &instructions {
        let next = instruction.next_ip();
        match instruction.flow_control() {
            FlowControl::ConditionalBranch => {
                conditional_branches += 1;
                let target = instruction.near_branch_target();
                if (start_ip..end_ip).contains(&target) {
                    leaders.insert(target);
                    leaders.insert(next);
                    if target <= instruction.ip() {
                        loops.insert(LoopCandidate {
                            header_rva: u32::try_from(target - image.image_base)?,
                            back_edge_rva: u32::try_from(instruction.ip() - image.image_base)?,
                        });
                    }
                }
            }
            FlowControl::UnconditionalBranch => {
                let target = instruction.near_branch_target();
                if (start_ip..end_ip).contains(&target) {
                    leaders.insert(target);
                    if target <= instruction.ip() {
                        loops.insert(LoopCandidate {
                            header_rva: u32::try_from(target - image.image_base)?,
                            back_edge_rva: u32::try_from(instruction.ip() - image.image_base)?,
                        });
                    }
                }
            }
            FlowControl::Call => direct_calls += 1,
            FlowControl::IndirectCall => indirect_calls += 1,
            _ => {}
        }
    }

    let jni_calls = trace_jni_origins(&instructions, image.image_base)?;
    let explored_path_states = explore_control_flow(
        &instructions,
        &by_ip,
        start_ip,
        end_ip,
        config,
        &mut truncated,
    );
    let mut loops = loops.into_iter().collect::<Vec<_>>();
    loops.sort_unstable_by_key(|item| (item.header_rva, item.back_edge_rva));

    Ok(NativeAnalysis {
        decoded_instructions: instructions.len(),
        basic_blocks: leaders.len(),
        conditional_branches,
        direct_calls,
        indirect_calls,
        explored_path_states,
        loops,
        jni_calls,
        truncated,
    })
}

fn trace_jni_origins(instructions: &[Instruction], image_base: u64) -> Result<Vec<JniCallSite>> {
    let mut registers = HashMap::<Register, Symbol>::new();
    let mut stack_slots = HashMap::<(Register, u64), Symbol>::new();
    registers.insert(Register::RCX, Symbol::EnvPointer);
    let mut sites = Vec::new();
    let mut seen = HashSet::new();

    for instruction in instructions {
        if instruction.flow_control() == FlowControl::IndirectCall
            && instruction.op0_kind() == OpKind::Memory
        {
            let base = instruction.memory_base().full_register();
            let displacement = instruction.memory_displacement64();
            if registers.get(&base) == Some(&Symbol::EnvTable)
                && displacement % 8 == 0
                && displacement / 8 < 236
            {
                let slot = usize::try_from(displacement / 8)?;
                if let Some(name) = function_name(slot) {
                    let rva = u32::try_from(instruction.ip() - image_base)?;
                    if seen.insert((rva, slot)) {
                        sites.push(JniCallSite {
                            rva,
                            slot,
                            name: name.to_owned(),
                        });
                    }
                }
            }
        }

        match instruction.mnemonic() {
            Mnemonic::Mov if instruction.op_count() >= 2 => {
                if instruction.op0_kind() == OpKind::Register {
                    let destination = instruction.op0_register().full_register();
                    let symbol = match instruction.op1_kind() {
                        OpKind::Register => registers
                            .get(&instruction.op1_register().full_register())
                            .copied(),
                        OpKind::Memory => {
                            let base = instruction.memory_base().full_register();
                            let displacement = instruction.memory_displacement64();
                            if registers.get(&base) == Some(&Symbol::EnvPointer)
                                && displacement == 0
                            {
                                Some(Symbol::EnvTable)
                            } else {
                                stack_slots.get(&(base, displacement)).copied()
                            }
                        }
                        _ => None,
                    };
                    if let Some(symbol) = symbol {
                        registers.insert(destination, symbol);
                    } else {
                        registers.remove(&destination);
                    }
                } else if instruction.op0_kind() == OpKind::Memory
                    && instruction.op1_kind() == OpKind::Register
                {
                    let base = instruction.memory_base().full_register();
                    if matches!(base, Register::RSP | Register::RBP) {
                        let key = (base, instruction.memory_displacement64());
                        if let Some(symbol) = registers
                            .get(&instruction.op1_register().full_register())
                            .copied()
                        {
                            stack_slots.insert(key, symbol);
                        } else {
                            stack_slots.remove(&key);
                        }
                    }
                }
            }
            Mnemonic::Lea
            | Mnemonic::Xor
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::Imul
            | Mnemonic::Pop
                if instruction.op0_kind() == OpKind::Register =>
            {
                registers.remove(&instruction.op0_register().full_register());
            }
            _ => {}
        }

        if matches!(
            instruction.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall
        ) {
            for register in [
                Register::RAX,
                Register::RCX,
                Register::RDX,
                Register::R8,
                Register::R9,
                Register::R10,
                Register::R11,
            ] {
                registers.remove(&register);
            }
        }
    }
    Ok(sites)
}

fn explore_control_flow(
    instructions: &[Instruction],
    by_ip: &HashMap<u64, usize>,
    start_ip: u64,
    end_ip: u64,
    config: TraceConfig,
    truncated: &mut bool,
) -> usize {
    let mut queue = VecDeque::from([start_ip]);
    let mut visits = HashMap::<u64, usize>::new();
    let mut explored = 0;
    while let Some(ip) = queue.pop_front() {
        if explored >= config.max_path_states {
            *truncated = true;
            break;
        }
        let count = visits.entry(ip).or_default();
        if *count >= config.max_visits_per_block {
            continue;
        }
        *count += 1;
        explored += 1;
        let Some(&index) = by_ip.get(&ip) else {
            continue;
        };
        let instruction = &instructions[index];
        let next = instruction.next_ip();
        let mut enqueue = |target: u64| {
            if (start_ip..end_ip).contains(&target) && by_ip.contains_key(&target) {
                queue.push_back(target);
            }
        };
        match instruction.flow_control() {
            FlowControl::ConditionalBranch => {
                enqueue(instruction.near_branch_target());
                enqueue(next);
            }
            FlowControl::UnconditionalBranch => enqueue(instruction.near_branch_target()),
            FlowControl::Return | FlowControl::Exception | FlowControl::Interrupt => {}
            _ => enqueue(next),
        }
    }
    explored
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits_are_nonzero() {
        let config = TraceConfig::default();
        assert!(config.max_instructions_per_method > 0);
        assert!(config.max_path_states > 0);
        assert!(config.max_visits_per_block > 0);
    }
}

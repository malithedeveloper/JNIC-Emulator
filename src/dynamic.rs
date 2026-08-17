use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::Rc;

use anyhow::Result;
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use unicorn_engine::unicorn_const::{Arch, HookType, Mode, Prot, Query};
use unicorn_engine::{RegisterX86, Unicorn};

use crate::classfile::{JavaClass, JavaMethod};
use crate::descriptor::{dotted, parse_method_descriptor};
use crate::dynamic_model::{DynamicConfig, DynamicMethodAnalysis};
use crate::jni::function_name;
use crate::loader_seeds::{LoaderSecrets, recover_loader_secrets};
use crate::pe::{PeImage, RuntimeFunction};

const PAGE: u64 = 0x1000;
const ENV_ADDRESS: u64 = 0x0020_0000_0000;
const JNI_TABLE_ADDRESS: u64 = 0x0020_0001_0000;
const STUB_ADDRESS: u64 = 0x0021_0000_0000;
const IMPORT_STUB_ADDRESS: u64 = 0x0021_0010_0000;
const SENTINEL_ADDRESS: u64 = 0x0021_0020_0000;
const HEAP_ADDRESS: u64 = 0x0030_0000_0000;
const HEAP_SIZE: u64 = 64 * 1024 * 1024;
const STREAM_ADDRESS: u64 = 0x0031_0000_0000;
const STACK_ADDRESS: u64 = 0x0040_0000_0000;
const STACK_SIZE: u64 = 8 * 1024 * 1024;
const JNI_SLOTS: usize = 236;

pub struct DynamicContext {
    image: PeImage,
    secrets: LoaderSecrets,
}

impl DynamicContext {
    pub fn new(image: &PeImage, classes: &[JavaClass]) -> Result<Self> {
        let secrets = recover_loader_secrets(image, classes)
            .map_err(anyhow::Error::msg)
            .map_err(|error| error.context("cannot prepare the loader's isolated state"))?;
        Ok(Self {
            image: PeImage::parse(image.bytes().to_vec())?,
            secrets,
        })
    }

    pub fn analyze_method(
        &self,
        class: &JavaClass,
        method: &JavaMethod,
        function: RuntimeFunction,
        config: DynamicConfig,
    ) -> DynamicMethodAnalysis {
        let mut paths = Vec::new();
        let mut queue = VecDeque::from([TraceScenario::default()]);
        let mut queued = HashSet::from([TraceScenario::default()]);
        let mut total_instructions = 0_usize;

        while let Some(scenario) = queue.pop_front() {
            if paths.len() >= config.max_scenarios_per_method {
                break;
            }
            let path = self.trace_scenario(class, method, function, config, scenario.clone());
            total_instructions += path.instructions;
            for branch in &path.branches {
                if branch.runtime_support || branch.condition.is_empty() {
                    continue;
                }
                let mut alternate = scenario.clone();
                if alternate.push(branch.rva, branch.occurrence, !branch.taken)
                    && queued.insert(alternate.clone())
                {
                    queue.push_back(alternate);
                }
            }
            paths.push(path);
        }

        let Some(best) = paths
            .iter()
            .filter(|path| path.completed && !path.statements.is_empty())
            .max_by_key(|path| path.statements.len())
            .or_else(|| paths.first())
        else {
            return DynamicMethodAnalysis::unavailable("dynamic trace did not start");
        };
        let mut analysis = DynamicMethodAnalysis {
            attempted: true,
            completed: best.completed,
            stop_reason: best.stop_reason.clone(),
            instructions: total_instructions,
            scenarios: paths.len(),
            jni_events: best.jni_events.clone(),
            java_body: best.statements.clone(),
            diagnostics: paths
                .iter()
                .filter(|path| !path.completed)
                .map(|path| format!("path {:?}: {}", path.scenario, path.stop_reason))
                .collect(),
        };
        if analysis.java_body.len() > config.max_statements_per_method {
            analysis
                .java_body
                .truncate(config.max_statements_per_method);
            analysis.stop_reason = "statement limit reached".to_owned();
        }
        analysis
    }

    fn trace_scenario(
        &self,
        class: &JavaClass,
        method: &JavaMethod,
        function: RuntimeFunction,
        config: DynamicConfig,
        scenario: TraceScenario,
    ) -> TracePath {
        let state = Rc::new(RefCell::new(TraceState::new(
            self,
            class,
            method,
            config,
            scenario.clone(),
        )));
        let hook_state = Rc::clone(&state);
        let mut emulator = match Unicorn::new(Arch::X86, Mode::MODE_64) {
            Ok(value) => value,
            Err(error) => {
                return TracePath::stopped(&scenario, 0, format!("Unicorn init failed: {error:?}"));
            }
        };
        if let Err(error) = prepare_memory(&mut emulator, self) {
            return TracePath::stopped(&scenario, 0, format!("memory setup failed: {error:?}"));
        }
        if let Err(error) = emulator.add_code_hook(1, 0, move |uc, address, size| {
            let mut state = hook_state.borrow_mut();
            state.on_code(uc, address, size);
        }) {
            return TracePath::stopped(&scenario, 0, format!("code hook failed: {error:?}"));
        }
        let invalid_state = Rc::clone(&state);
        if let Err(error) = emulator.add_mem_hook(
            HookType::MEM_INVALID,
            1,
            0,
            move |uc, kind, address, size, _value| {
                let mut state = invalid_state.borrow_mut();
                state.on_invalid_memory(uc, kind, address, size)
            },
        ) {
            return TracePath::stopped(&scenario, 0, format!("memory hook failed: {error:?}"));
        }

        {
            let mut state = state.borrow_mut();
            state.initialize_arguments(&mut emulator);
        }
        let entry = self.image.image_base + u64::from(function.begin);
        let status = emulator.emu_start(
            entry,
            SENTINEL_ADDRESS,
            config.timeout_micros_per_scenario,
            config.max_instructions_per_scenario,
        );
        let timeout = emulator.query(Query::TIMEOUT).unwrap_or(0) != 0;
        let mut state = state.borrow_mut();
        if !state.reached_sentinel
            && emulator
                .reg_read(RegisterX86::RIP)
                .is_ok_and(|rip| rip == SENTINEL_ADDRESS)
        {
            state.capture_return(&mut emulator);
            state.reached_sentinel = true;
        }
        if state.stop_reason.is_empty() {
            if state.reached_sentinel {
                state.stop_reason = "returned normally".to_owned();
            } else if state.instruction_limit {
                state.stop_reason = "instruction limit reached".to_owned();
            } else if timeout {
                state.stop_reason = "time limit reached".to_owned();
            } else {
                state.stop_reason = format!("emulator stopped: {status:?}");
            }
        }
        state.finish()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
struct TraceScenario {
    predicates: Vec<ForcedPredicate>,
}

impl TraceScenario {
    fn push(&mut self, rva: u32, occurrence: usize, outcome: bool) -> bool {
        if self.predicates.len() >= 8
            || self.predicates.iter().any(|predicate| predicate.rva == rva)
        {
            return false;
        }
        self.predicates.push(ForcedPredicate {
            rva,
            occurrence,
            outcome,
        });
        true
    }

    fn wants(&self, rva: u32, occurrence: usize) -> Option<bool> {
        self.predicates
            .iter()
            .find(|predicate| predicate.rva == rva && predicate.occurrence == occurrence)
            .map(|predicate| predicate.outcome)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ForcedPredicate {
    rva: u32,
    occurrence: usize,
    outcome: bool,
}

#[derive(Debug, Clone)]
struct SemanticBranch {
    rva: u32,
    occurrence: usize,
    condition: String,
    taken: bool,
    runtime_support: bool,
}

#[derive(Debug, Clone)]
struct TracePath {
    scenario: TraceScenario,
    statements: Vec<String>,
    branches: Vec<SemanticBranch>,
    jni_events: Vec<String>,
    completed: bool,
    instructions: usize,
    stop_reason: String,
}

impl TracePath {
    fn stopped(scenario: &TraceScenario, instructions: usize, reason: String) -> Self {
        Self {
            scenario: scenario.clone(),
            statements: Vec::new(),
            branches: Vec::new(),
            jni_events: Vec::new(),
            completed: false,
            instructions,
            stop_reason: reason,
        }
    }
}

#[derive(Debug, Clone)]
struct Value {
    expression: Option<String>,
}

impl Value {
    fn unknown() -> Self {
        Self { expression: None }
    }

    fn expression(expression: impl Into<String>) -> Self {
        Self {
            expression: Some(expression.into()),
        }
    }
}

#[derive(Debug, Clone)]
struct Handle {
    kind: HandleKind,
    text: String,
    name: String,
    descriptor: String,
    owner: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandleKind {
    Class,
    Method,
    Field,
    String,
    Object,
}

struct TraceState<'a> {
    context: &'a DynamicContext,
    class_name: String,
    method: JavaMethod,
    config: DynamicConfig,
    scenario: TraceScenario,
    instructions: HashMap<u64, Instruction>,
    registers: HashMap<Register, Value>,
    memory: HashMap<(u64, u8), Value>,
    handles: HashMap<u64, Handle>,
    object_classes: HashMap<u64, String>,
    field_values: HashMap<(u64, u64), i64>,
    pending_comparison: Option<(Value, Value)>,
    statements: Vec<String>,
    branches: Vec<SemanticBranch>,
    jni_events: Vec<String>,
    predicate_occurrences: HashMap<u32, usize>,
    heap_next: u64,
    counters: HashMap<&'static str, usize>,
    instruction_count: usize,
    reached_sentinel: bool,
    instruction_limit: bool,
    stop_reason: String,
}

impl<'a> TraceState<'a> {
    fn new(
        context: &'a DynamicContext,
        class: &JavaClass,
        method: &JavaMethod,
        config: DynamicConfig,
        scenario: TraceScenario,
    ) -> Self {
        Self {
            context,
            class_name: class.internal_name.clone(),
            method: method.clone(),
            config,
            scenario,
            instructions: HashMap::new(),
            registers: HashMap::new(),
            memory: HashMap::new(),
            handles: HashMap::new(),
            object_classes: HashMap::new(),
            field_values: HashMap::new(),
            pending_comparison: None,
            statements: Vec::new(),
            branches: Vec::new(),
            jni_events: Vec::new(),
            predicate_occurrences: HashMap::new(),
            heap_next: HEAP_ADDRESS + 0x1000,
            counters: HashMap::new(),
            instruction_count: 0,
            reached_sentinel: false,
            instruction_limit: false,
            stop_reason: String::new(),
        }
    }

    fn on_code(&mut self, uc: &mut Unicorn<'_, ()>, address: u64, size: u32) {
        if self.stop_reason.len() >= 160 {
            return;
        }
        if address == SENTINEL_ADDRESS {
            self.capture_return(uc);
            self.reached_sentinel = true;
            self.stop_reason = "returned normally".to_owned();
            let _ = uc.emu_stop();
            return;
        }
        if let Some(slot) = jni_slot(address) {
            self.handle_jni(uc, slot);
            return;
        }
        if let Some(index) = import_slot(address) {
            self.handle_import(uc, index);
            return;
        }

        self.instruction_count += 1;
        if self.instruction_count >= self.config.max_instructions_per_scenario {
            self.instruction_limit = true;
            self.stop_reason = "instruction limit reached".to_owned();
            let _ = uc.emu_stop();
            return;
        }

        let instruction = self.decode(uc, address, size);
        if instruction.is_invalid() {
            self.stop_reason = format!("invalid instruction at RVA 0x{:x}", self.rva(address));
            let _ = uc.emu_stop();
            return;
        }
        if instruction.mnemonic() == Mnemonic::Int3 || instruction.mnemonic() == Mnemonic::Ud2 {
            self.stop_reason = format!("native trap at RVA 0x{:x}", self.rva(address));
            let _ = uc.emu_stop();
            return;
        }

        self.shadow_step(uc, &instruction);
    }

    fn on_invalid_memory(
        &mut self,
        uc: &mut Unicorn<'_, ()>,
        _kind: unicorn_engine::MemType,
        address: u64,
        size: usize,
    ) -> bool {
        self.stop_reason = format!(
            "isolated memory fault at 0x{address:x} (RVA 0x{:x}, {size} bytes)",
            self.rva(address)
        );
        let _ = uc.emu_stop();
        false
    }

    fn rva(&self, address: u64) -> u32 {
        address
            .checked_sub(self.context.image.image_base)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0)
    }

    fn decode(&mut self, uc: &mut Unicorn<'_, ()>, address: u64, size: u32) -> Instruction {
        if let Some(instruction) = self.instructions.get(&address) {
            return *instruction;
        }
        let read_size = if size == 0 { 16 } else { size as usize }.max(16);
        let bytes = uc.mem_read_as_vec(address, read_size).unwrap_or_default();
        let mut decoder = Decoder::with_ip(64, &bytes, address, DecoderOptions::NONE);
        let instruction = decoder.decode();
        self.instructions.insert(address, instruction);
        instruction
    }

    fn initialize_arguments(&mut self, uc: &mut Unicorn<'_, ()>) {
        let stack_pointer = STACK_ADDRESS + STACK_SIZE - 0x1008;
        let _ = uc.mem_write(stack_pointer, &SENTINEL_ADDRESS.to_le_bytes());
        let _ = uc.reg_write(RegisterX86::RSP, stack_pointer);
        let is_static = self.method.access & 0x0008 != 0;
        let receiver = self.make_handle(
            HandleKind::Class,
            if is_static { "ClassRef" } else { "this" },
            "",
            "",
            &dotted(&self.class_name),
        );
        if !is_static {
            self.object_classes
                .insert(receiver, self.class_name.clone());
            self.registers
                .insert(Register::RDX, Value::expression("this"));
        } else {
            self.registers.insert(
                Register::RDX,
                Value::expression(format!("{}.class", dotted(&self.class_name))),
            );
        }
        let _ = uc.reg_write(RegisterX86::RCX, ENV_ADDRESS);
        let _ = uc.reg_write(RegisterX86::RDX, receiver);
        self.registers.insert(Register::RCX, Value::unknown());

        let kinds = parameter_kinds(&self.method.descriptor);
        for index in 0..kinds.len().max(12) {
            let kind = kinds.get(index).copied().unwrap_or(b'I');
            let mut value = (index as u64) + 1;
            if matches!(kind, b'L' | b'[') {
                let name = format!("arg{index}");
                value = self.make_handle(HandleKind::Object, &name, "", "", "");
            } else if kind == b'Z' {
                value = 0;
            }
            let expression = Value::expression(format!("arg{index}"));
            match index {
                0 => {
                    let _ = uc.reg_write(RegisterX86::R8, value);
                    self.registers.insert(Register::R8, expression);
                }
                1 => {
                    let _ = uc.reg_write(RegisterX86::R9, value);
                    self.registers.insert(Register::R9, expression);
                }
                _ => {
                    let address =
                        stack_pointer + 0x28 + (u64::try_from(index).unwrap_or(12) - 2) * 8;
                    let _ = uc.mem_write(address, &value.to_le_bytes());
                    self.memory.insert((address, 8), expression);
                }
            }
        }
    }

    fn make_handle(
        &mut self,
        kind: HandleKind,
        text: &str,
        name: &str,
        descriptor: &str,
        owner: &str,
    ) -> u64 {
        let address = self.heap_next;
        self.heap_next = self.heap_next.saturating_add(16);
        self.handles.insert(
            address,
            Handle {
                kind,
                text: text.to_owned(),
                name: name.to_owned(),
                descriptor: descriptor.to_owned(),
                owner: owner.to_owned(),
            },
        );
        address
    }

    fn next_name(&mut self, prefix: &'static str) -> String {
        let value = self.counters.entry(prefix).or_insert(0);
        *value += 1;
        format!("{prefix}{value}")
    }

    fn shadow_step(&mut self, uc: &mut Unicorn<'_, ()>, instruction: &Instruction) {
        match instruction.mnemonic() {
            Mnemonic::Mov
            | Mnemonic::Movsx
            | Mnemonic::Movzx
            | Mnemonic::Movsxd
            | Mnemonic::Cmove
            | Mnemonic::Cmovne
            | Mnemonic::Cmovg
            | Mnemonic::Cmovl
            | Mnemonic::Cmovge
            | Mnemonic::Cmovle => {
                if instruction.op_count() >= 2 && instruction.op0_kind() == OpKind::Register {
                    let value = self.read_operand(uc, instruction, 1);
                    let register = instruction.op0_register().full_register();
                    self.registers.insert(register, value);
                }
            }
            Mnemonic::Lea => {
                if instruction.op_count() >= 2 && instruction.op0_kind() == OpKind::Register {
                    let value = self.read_lea(instruction);
                    self.registers
                        .insert(instruction.op0_register().full_register(), value);
                }
            }
            Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::Imul
            | Mnemonic::Xor
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Shl
            | Mnemonic::Shr
            | Mnemonic::Sar
            | Mnemonic::Addsd
            | Mnemonic::Subsd
            | Mnemonic::Mulsd
            | Mnemonic::Addss
            | Mnemonic::Subss
            | Mnemonic::Mulss => {
                if instruction.op_count() >= 2 && instruction.op0_kind() == OpKind::Register {
                    let left = self.read_operand(uc, instruction, 0);
                    let right = self.read_operand(uc, instruction, 1);
                    let expression = match (left.expression, right.expression) {
                        (Some(left), Some(right)) => Some(format!(
                            "({left} {} {right})",
                            operator(instruction.mnemonic())
                        )),
                        _ => None,
                    };
                    self.registers.insert(
                        instruction.op0_register().full_register(),
                        Value { expression },
                    );
                }
            }
            Mnemonic::Inc | Mnemonic::Dec => {
                if instruction.op0_kind() == OpKind::Register {
                    let value = self.read_operand(uc, instruction, 0);
                    let operation = if instruction.mnemonic() == Mnemonic::Inc {
                        "+"
                    } else {
                        "-"
                    };
                    let expression = value
                        .expression
                        .map(|expression| format!("({expression} {operation} 1)"));
                    self.registers.insert(
                        instruction.op0_register().full_register(),
                        Value { expression },
                    );
                }
            }
            Mnemonic::Cmp | Mnemonic::Test => {
                if instruction.op_count() >= 2 {
                    self.pending_comparison = Some((
                        self.read_operand(uc, instruction, 0),
                        self.read_operand(uc, instruction, 1),
                    ));
                }
            }
            Mnemonic::Call => {
                self.registers.insert(Register::RAX, Value::unknown());
            }
            _ => {}
        }
        if is_conditional_jump(instruction) {
            self.handle_conditional(uc, instruction);
        }
    }

    fn read_operand(
        &mut self,
        uc: &mut Unicorn<'_, ()>,
        instruction: &Instruction,
        index: u32,
    ) -> Value {
        match instruction.op_kind(index) {
            OpKind::Register => self
                .registers
                .get(&instruction.op_register(index).full_register())
                .cloned()
                .unwrap_or_else(Value::unknown),
            OpKind::Immediate8
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate32to64
            | OpKind::Immediate64 => Value::expression(format!("{}", instruction.immediate(index))),
            OpKind::Memory => {
                let address = self.memory_address(uc, instruction, index);
                let size = instruction.memory_size().size().min(8) as u8;
                if let Some(value) = address.and_then(|address| self.memory.get(&(address, size))) {
                    return value.clone();
                }
                Value::unknown()
            }
            _ => Value::unknown(),
        }
    }

    fn read_lea(&self, instruction: &Instruction) -> Value {
        if instruction.memory_base() == Register::RIP {
            return Value::unknown();
        }
        let base = instruction.memory_base().full_register();
        let base_value = self
            .registers
            .get(&base)
            .cloned()
            .unwrap_or_else(Value::unknown);
        let mut expression = base_value.expression;
        let scale = instruction.memory_index_scale();
        if instruction.memory_index() != Register::None {
            let index = self
                .registers
                .get(&instruction.memory_index().full_register())
                .and_then(|value| value.expression.clone());
            if let Some(index) = index {
                let index_expression = if scale == 1 {
                    index
                } else {
                    format!("({index} * {scale})")
                };
                expression = Some(match expression {
                    Some(base) => format!("({base} + {index_expression})"),
                    None => index_expression,
                });
            }
        }
        Value { expression }
    }

    fn memory_address(
        &self,
        uc: &Unicorn<'_, ()>,
        instruction: &Instruction,
        _index: u32,
    ) -> Option<u64> {
        if instruction.memory_base() == Register::RIP {
            return instruction
                .ip()
                .checked_add(u64::try_from(instruction.len()).ok()?)?
                .checked_add_signed(i64::try_from(instruction.memory_displacement64()).ok()?);
        }
        let base = uc
            .reg_read(register_id(instruction.memory_base().full_register()))
            .ok()?;
        let index = if instruction.memory_index() == Register::None {
            0
        } else {
            uc.reg_read(register_id(instruction.memory_index().full_register()))
                .ok()?
                .wrapping_mul(u64::from(instruction.memory_index_scale()))
        };
        Some(
            base.wrapping_add(index).wrapping_add_signed(
                i64::try_from(instruction.memory_displacement64()).unwrap_or(0),
            ),
        )
    }

    fn handle_conditional(&mut self, uc: &mut Unicorn<'_, ()>, instruction: &Instruction) {
        let rva = self.rva(instruction.ip());
        let occurrence = *self.predicate_occurrences.entry(rva).or_insert(0);
        self.predicate_occurrences.insert(rva, occurrence + 1);
        let (left, right) = self
            .pending_comparison
            .clone()
            .unwrap_or_else(|| (Value::unknown(), Value::unknown()));
        let left_unknown = left.expression.is_none();
        let condition = match (left.expression, right.expression) {
            (Some(left), Some(right)) => format!(
                "{left} {} {right}",
                conditional_operator(instruction.mnemonic())
            ),
            _ => return,
        };
        let mut taken = actual_condition(uc, instruction.mnemonic());
        if let Some(desired) = self.scenario.wants(rva, occurrence) {
            if force_condition(uc, instruction.mnemonic(), desired) {
                taken = desired;
            }
        }
        let runtime_support = condition.contains("exception")
            || condition.contains("pendingException")
            || condition.contains("handle(")
            || left_unknown;
        self.branches.push(SemanticBranch {
            rva,
            occurrence,
            condition,
            taken,
            runtime_support,
        });
        self.pending_comparison = None;
    }

    fn capture_return(&mut self, uc: &mut Unicorn<'_, ()>) {
        let Ok(descriptor) = parse_method_descriptor(&self.method.descriptor) else {
            return;
        };
        if descriptor.result == "void" {
            return;
        }
        let register = if matches!(descriptor.result.as_str(), "float" | "double") {
            Register::XMM0
        } else {
            Register::RAX
        };
        let value = self
            .registers
            .get(&register)
            .cloned()
            .unwrap_or_else(Value::unknown);
        if let Some(expression) = value.expression {
            self.statements.push(format!("return {expression};"));
        } else if matches!(descriptor.result.as_str(), "java.lang.Object" | "void") {
            self.statements.push("return null;".to_owned());
        } else if let Some(handle) = uc
            .reg_read(RegisterX86::RAX)
            .ok()
            .and_then(|value| self.handle_text(value))
        {
            self.statements.push(format!("return {handle};"));
        }
    }

    fn handle_text(&self, handle: u64) -> Option<String> {
        self.handles.get(&handle).map(|item| {
            if item.text.is_empty() {
                item.kind.to_display().to_owned()
            } else {
                item.text.clone()
            }
        })
    }

    fn finish(&mut self) -> TracePath {
        TracePath {
            scenario: self.scenario.clone(),
            statements: std::mem::take(&mut self.statements),
            branches: std::mem::take(&mut self.branches),
            jni_events: std::mem::take(&mut self.jni_events),
            completed: self.reached_sentinel,
            instructions: self.instruction_count,
            stop_reason: self.stop_reason.clone(),
        }
    }

    fn handle_jni(&mut self, uc: &mut Unicorn<'_, ()>, slot: usize) {
        let Some(name) = function_name(slot) else {
            return;
        };
        let arg1 = read_register(uc, RegisterX86::RDX);
        let arg2 = read_register(uc, RegisterX86::R8);
        let arg3 = read_register(uc, RegisterX86::R9);
        match name {
            "FindClass" => {
                let class_name = self.read_c_string(uc, arg1);
                self.jni_events
                    .push(format!("FindClass({})", quote_java(&class_name)));
                let handle = self.make_handle(
                    HandleKind::Class,
                    &format!("ClassRef({})", quote_java(&class_name)),
                    &class_name,
                    "",
                    "",
                );
                set_result(uc, self, Register::RAX, Value::unknown(), Some(handle));
            }
            "GetMethodID" | "GetStaticMethodID" | "GetFieldID" | "GetStaticFieldID" => {
                let member_name = self.read_c_string(uc, arg2);
                let descriptor = self.read_c_string(uc, arg3);
                self.jni_events.push(format!(
                    "{name}({}, {})",
                    quote_java(&member_name),
                    quote_java(&descriptor)
                ));
                let owner = self
                    .handles
                    .get(&arg1)
                    .map(|handle| handle.name.clone())
                    .unwrap_or_default();
                let kind = if name.contains("Method") {
                    HandleKind::Method
                } else {
                    HandleKind::Field
                };
                let handle = self.make_handle(kind, "", &member_name, &descriptor, &owner);
                set_result(uc, self, Register::RAX, Value::unknown(), Some(handle));
            }
            "NewStringUTF" | "NewString" => {
                let value = if name == "NewStringUTF" {
                    self.read_c_string(uc, arg1)
                } else {
                    self.read_utf16(uc, arg1, usize::try_from(arg2).unwrap_or(0))
                };
                let quoted = quote_java(&value);
                let handle = self.make_handle(HandleKind::String, &quoted, "", &value, "");
                set_result(
                    uc,
                    self,
                    Register::RAX,
                    Value::expression(quoted),
                    Some(handle),
                );
            }
            "GetStaticObjectField" | "GetObjectField" => {
                let field = self.handles.get(&arg2).cloned();
                let owner = field
                    .as_ref()
                    .map(|field| dotted(&field.owner))
                    .unwrap_or_default();
                let field_name = field
                    .as_ref()
                    .map(|field| field.name.clone())
                    .unwrap_or_default();
                let text = if owner.is_empty() {
                    field_name.clone()
                } else {
                    format!("{owner}.{field_name}")
                };
                let handle = self.make_handle(
                    HandleKind::Object,
                    &text,
                    &field_name,
                    "",
                    field
                        .as_ref()
                        .map(|field| field.owner.clone())
                        .unwrap_or_default()
                        .as_str(),
                );
                if name == "GetStaticObjectField" && matches!(field_name.as_str(), "out" | "err") {
                    if let Some(handle) = self.handles.get_mut(&handle) {
                        handle.text = format!("System.{field_name}");
                    }
                }
                set_result(
                    uc,
                    self,
                    Register::RAX,
                    Value::expression(text),
                    Some(handle),
                );
            }
            "GetStaticIntField" | "GetIntField" | "GetStaticLongField" | "GetLongField" => {
                let expression = self.field_expression(arg1, arg2);
                let value = self.field_values.get(&(arg1, arg2)).copied().unwrap_or(0);
                set_integer_result(uc, self, value, Value::expression(expression));
            }
            "SetStaticIntField" | "SetIntField" | "SetStaticLongField" | "SetLongField" => {
                let expression = self.field_expression(arg1, arg2);
                self.field_values.insert((arg1, arg2), arg3 as i64);
                self.statements
                    .push(format!("{expression} = {};", render_u64(arg3)));
                set_integer_result(uc, self, 0, Value::unknown());
            }
            "CallVoidMethod"
            | "CallStaticVoidMethod"
            | "CallNonvirtualVoidMethod"
            | "CallObjectMethod"
            | "CallStaticObjectMethod"
            | "CallNonvirtualObjectMethod"
            | "CallBooleanMethod"
            | "CallStaticBooleanMethod"
            | "CallIntMethod"
            | "CallStaticIntMethod"
            | "CallLongMethod"
            | "CallStaticLongMethod"
            | "CallFloatMethod"
            | "CallDoubleMethod" => {
                self.handle_call(uc, name);
            }
            "NewObject" | "NewObjectA" | "NewObjectV" | "AllocObject" => {
                self.handle_new_object(uc, name);
            }
            "ThrowNew" => {
                let class_handle = self.handles.get(&arg1).cloned();
                let message = self.read_c_string(uc, arg2);
                let type_name = class_handle
                    .as_ref()
                    .map(|handle| dotted(&handle.name))
                    .unwrap_or_else(|| "java.lang.RuntimeException".to_owned());
                self.statements
                    .push(format!("throw new {type_name}({});", quote_java(&message)));
                let handle = self.make_handle(
                    HandleKind::Object,
                    &format!("new {type_name}({})", quote_java(&message)),
                    "",
                    "",
                    "",
                );
                set_result(uc, self, Register::RAX, Value::unknown(), Some(handle));
            }
            "Throw" => {
                let expression = self
                    .handle_text(arg1)
                    .unwrap_or_else(|| "throwable".to_owned());
                self.statements.push(format!("throw {expression};"));
                set_integer_result(uc, self, 0, Value::unknown());
            }
            "ExceptionCheck" => {
                set_integer_result(uc, self, 0, Value::expression("pendingException == null"));
            }
            "FatalError" => {
                self.stop_reason = "FatalError path reached in isolated emulation".to_owned();
                let _ = uc.emu_stop();
            }
            _ => {
                set_integer_result(uc, self, 0, Value::unknown());
            }
        }
        self.jni_events
            .push(format!("{name} @ RVA 0x{:x}", self.call_site_rva(uc)));
    }

    fn handle_call(&mut self, uc: &mut Unicorn<'_, ()>, name: &str) {
        let method_handle_value = if name.starts_with("CallNonvirtual") {
            read_register(uc, RegisterX86::R9)
        } else {
            read_register(uc, RegisterX86::R8)
        };
        let Some(method) = self.handles.get(&method_handle_value).cloned() else {
            set_integer_result(uc, self, 0, Value::unknown());
            return;
        };
        let receiver_register = Register::RDX;
        let receiver = self
            .registers
            .get(&receiver_register)
            .cloned()
            .and_then(|value| value.expression)
            .or_else(|| self.handle_text(read_register(uc, RegisterX86::RDX)))
            .unwrap_or_else(|| "receiver".to_owned());
        let arguments = self.call_arguments(uc, &method.descriptor);
        let owner = dotted(&method.owner);
        let target =
            if name.starts_with("CallStatic") || receiver == "receiver" || receiver.is_empty() {
                if owner.is_empty() {
                    "this".to_owned()
                } else {
                    owner
                }
            } else if receiver == "out" || receiver == "System.out" {
                "System.out".to_owned()
            } else if receiver == "err" || receiver == "System.err" {
                "System.err".to_owned()
            } else if method.owner == "java/lang/System" && method.name == "currentTimeMillis" {
                "System".to_owned()
            } else {
                receiver
            };
        let invocation = if method.owner == "java/lang/StringBuilder" && method.name == "append" {
            format!(
                "{target} += {}",
                arguments
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "\"\"".to_owned())
            )
        } else if method.name == "<init>" {
            if arguments.is_empty() {
                format!("{target}()")
            } else {
                format!("{target}({})", arguments.join(", "))
            }
        } else {
            format!("{target}.{}({})", method.name, arguments.join(", "))
        };
        let result_expression = Value::expression(invocation.clone());
        match name {
            _ if name.contains("Void") => {
                if method.name != "<init>" || !arguments.is_empty() {
                    self.statements.push(format!("{invocation};"));
                }
                set_integer_result(uc, self, 0, Value::unknown());
            }
            _ if name.contains("Boolean") => set_integer_result(uc, self, 1, result_expression),
            _ if name.contains("Int") || name.contains("Long") => {
                set_integer_result(uc, self, 0, result_expression)
            }
            _ => {
                let result_type = parse_method_descriptor(&method.descriptor)
                    .map(|d| d.result)
                    .unwrap_or_else(|_| "java.lang.Object".to_owned());
                let var = self.next_name("result");
                self.statements
                    .push(format!("{result_type} {var} = {invocation};"));
                let handle = self.make_handle(
                    HandleKind::Object,
                    &var,
                    &method.name,
                    &method.descriptor,
                    &method.owner,
                );
                set_result(
                    uc,
                    self,
                    Register::RAX,
                    Value::expression(var),
                    Some(handle),
                );
            }
        }
    }

    fn handle_new_object(&mut self, uc: &mut Unicorn<'_, ()>, name: &str) {
        let class_value = read_register(uc, RegisterX86::RDX);
        let class_handle = self.handles.get(&class_value).cloned();
        let type_name = class_handle
            .as_ref()
            .map(|handle| dotted(&handle.name))
            .unwrap_or_else(|| "java.lang.Object".to_owned());
        if name == "AllocObject" {
            let variable = self.next_name("object");
            let handle = self.make_handle(
                HandleKind::Object,
                &variable,
                "",
                "",
                &class_handle
                    .as_ref()
                    .map(|handle| handle.name.clone())
                    .unwrap_or_default(),
            );
            self.statements
                .push(format!("{type_name} {variable} = new {type_name}();"));
            set_result(
                uc,
                self,
                Register::RAX,
                Value::expression(variable),
                Some(handle),
            );
            return;
        }
        let variable = self.next_name("object");
        let arguments = self.constructor_arguments(uc);
        let handle = self.make_handle(
            HandleKind::Object,
            &variable,
            "",
            "",
            &class_handle
                .as_ref()
                .map(|handle| handle.name.clone())
                .unwrap_or_default(),
        );
        self.statements.push(format!(
            "{type_name} {variable} = new {type_name}({});",
            arguments.join(", ")
        ));
        set_result(
            uc,
            self,
            Register::RAX,
            Value::expression(variable),
            Some(handle),
        );
    }

    fn constructor_arguments(&mut self, uc: &mut Unicorn<'_, ()>) -> Vec<String> {
        let values = [
            read_register(uc, RegisterX86::R9),
            self.stack_value(uc, 1).unwrap_or(0),
            self.stack_value(uc, 2).unwrap_or(0),
        ];
        values
            .iter()
            .map(|value| self.render_scalar_or_handle(*value))
            .collect()
    }

    fn call_arguments(&mut self, uc: &mut Unicorn<'_, ()>, descriptor: &str) -> Vec<String> {
        let Ok(parsed) = parse_method_descriptor(descriptor) else {
            return Vec::new();
        };
        let mut values = VecDeque::from([
            read_register(uc, RegisterX86::R9),
            self.stack_value(uc, 1).unwrap_or(0),
            self.stack_value(uc, 2).unwrap_or(0),
            self.stack_value(uc, 3).unwrap_or(0),
        ]);
        parsed
            .parameters
            .iter()
            .map(|parameter| {
                let value = values.pop_front().unwrap_or(0);
                if parameter == "java.lang.String" {
                    self.handle_text(value).unwrap_or_else(|| "null".to_owned())
                } else {
                    self.render_scalar_or_handle(value)
                }
            })
            .collect()
    }

    fn render_scalar_or_handle(&self, value: u64) -> String {
        if let Some(text) = self.handle_text(value) {
            return text;
        }
        if value <= u32::MAX as u64 {
            format!("{}", (value as u32) as i32)
        } else if value <= i64::MAX as u64 {
            format!("{}", value as i64)
        } else {
            format!("{value}")
        }
    }

    fn field_expression(&self, receiver: u64, field: u64) -> String {
        let Some(handle) = self.handles.get(&field) else {
            return "field".to_owned();
        };
        if handle.owner.is_empty() {
            return handle.name.clone();
        }
        if self.object_classes.contains_key(&receiver)
            || self
                .handles
                .get(&receiver)
                .is_some_and(|item| item.kind == HandleKind::Object)
        {
            let receiver_text = self
                .handle_text(receiver)
                .unwrap_or_else(|| "receiver".to_owned());
            format!("{receiver_text}.{}", handle.name)
        } else {
            format!("{}.{}", dotted(&handle.owner), handle.name)
        }
    }

    fn stack_value(&self, uc: &Unicorn<'_, ()>, index: u64) -> Option<u64> {
        let stack = uc.reg_read(RegisterX86::RSP).ok()?;
        let address = stack.checked_add(8 + index * 8)?;
        let bytes = uc.mem_read_as_vec(address, 8).ok()?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    }

    fn call_site_rva(&self, uc: &Unicorn<'_, ()>) -> u32 {
        let stack = uc.reg_read(RegisterX86::RSP).unwrap_or(0);
        self.stack_value_with_base(uc, stack, 0)
            .and_then(|return_address| return_address.checked_sub(self.context.image.image_base))
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0)
    }

    fn stack_value_with_base(&self, uc: &Unicorn<'_, ()>, base: u64, index: u64) -> Option<u64> {
        let address = base.checked_add(8 + index * 8)?;
        let bytes = uc.mem_read_as_vec(address, 8).ok()?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    }

    fn handle_import(&mut self, uc: &mut Unicorn<'_, ()>, index: usize) {
        let Some(import) = self.context.image.imports.get(index) else {
            return;
        };
        let arg1 = read_register(uc, RegisterX86::RCX);
        let arg2 = read_register(uc, RegisterX86::RDX);
        let arg3 = read_register(uc, RegisterX86::R8);
        match import.name.as_str() {
            "malloc" | "realloc" => {
                let size = if import.name == "malloc" { arg1 } else { arg2 };
                let address = self.allocate(usize::try_from(size).unwrap_or(0));
                set_result(
                    uc,
                    self,
                    Register::RAX,
                    Value::unknown(),
                    u64_to_option(address),
                );
            }
            "calloc" => {
                let size = usize::try_from(arg1.saturating_mul(arg2)).unwrap_or(0);
                let address = self.allocate(size);
                set_result(
                    uc,
                    self,
                    Register::RAX,
                    Value::unknown(),
                    u64_to_option(address),
                );
            }
            "strlen" => {
                let value = self.read_c_string(uc, arg1).len() as i64;
                set_integer_result(uc, self, value, Value::unknown());
            }
            "strncmp" => {
                let left = self.read_c_string(uc, arg1);
                let right = self.read_c_string(uc, arg2);
                let count = usize::try_from(arg3).unwrap_or(left.len().min(right.len()));
                set_integer_result(
                    uc,
                    self,
                    compare_prefix(&left, &right, count),
                    Value::unknown(),
                );
            }
            "abort" | "_amsg_exit" | "exit" => {
                self.stop_reason = format!("native abort path reached through {}", import.name);
                let _ = uc.emu_stop();
            }
            _ => set_integer_result(uc, self, 0, Value::unknown()),
        }
    }

    fn allocate(&mut self, size: usize) -> Option<u64> {
        let amount = (size.max(16) + 15) & !15;
        if amount as u64 > HEAP_SIZE || self.heap_next > HEAP_ADDRESS + HEAP_SIZE - amount as u64 {
            self.stop_reason = "isolated heap budget reached".to_owned();
            return None;
        }
        let address = self.heap_next;
        self.heap_next += amount as u64;
        Some(address)
    }

    fn read_c_string(&self, uc: &Unicorn<'_, ()>, address: u64) -> String {
        if address == 0 {
            return String::new();
        }
        let bytes = uc.mem_read_as_vec(address, 4096).unwrap_or_default();
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    }

    fn read_utf16(&self, uc: &Unicorn<'_, ()>, address: u64, count: usize) -> String {
        if address == 0 || count > 4096 {
            return String::new();
        }
        let bytes = uc
            .mem_read_as_vec(address, count.saturating_mul(2))
            .unwrap_or_default();
        bytes
            .chunks_exact(2)
            .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
            .collect::<Vec<_>>()
            .iter()
            .map(|unit| char::from_u32(u32::from(*unit)).unwrap_or('\u{FFFD}'))
            .collect()
    }
}

impl HandleKind {
    fn to_display(self) -> &'static str {
        match self {
            Self::Class => "ClassRef",
            Self::Method => "MethodRef",
            Self::Field => "FieldRef",
            Self::String => "StringRef",
            Self::Object => "objectRef",
        }
    }
}

fn prepare_memory(
    uc: &mut Unicorn<'_, ()>,
    context: &DynamicContext,
) -> Result<(), unicorn_engine::uc_error> {
    let image = &context.image;
    let image_size = align_up(u64::from(image.image_size), PAGE);
    uc.mem_map(image.image_base, image_size, Prot::ALL)?;
    let header_size = image.bytes().len().min(PAGE as usize);
    uc.mem_write(image.image_base, &image.bytes()[..header_size])?;
    for section in &image.sections {
        if section.raw_size == 0 {
            continue;
        }
        let offset =
            usize::try_from(section.raw_offset).map_err(|_| unicorn_engine::uc_error::ARG)?;
        let length =
            usize::try_from(section.raw_size).map_err(|_| unicorn_engine::uc_error::ARG)?;
        let bytes = image
            .bytes()
            .get(offset..offset.checked_add(length).unwrap_or(0))
            .unwrap_or(&[]);
        uc.mem_write(image.image_base + u64::from(section.virtual_address), bytes)?;
    }

    uc.mem_map(ENV_ADDRESS, 0x20000, Prot::READ | Prot::WRITE)?;
    uc.mem_map(STUB_ADDRESS, 0x10000, Prot::READ | Prot::EXEC)?;
    uc.mem_map(HEAP_ADDRESS, HEAP_SIZE, Prot::READ | Prot::WRITE)?;
    uc.mem_map(STACK_ADDRESS, STACK_SIZE, Prot::READ | Prot::WRITE)?;
    uc.mem_map(
        STREAM_ADDRESS,
        align_up(context.secrets.keystream.len() as u64, PAGE),
        Prot::READ | Prot::WRITE,
    )?;
    uc.mem_write(ENV_ADDRESS, &JNI_TABLE_ADDRESS.to_le_bytes())?;
    let returns = vec![0xC3_u8; 0x10000];
    uc.mem_write(STUB_ADDRESS, &returns)?;
    for slot in 0..JNI_SLOTS {
        let stub = STUB_ADDRESS + slot as u64 * 16;
        uc.mem_write(JNI_TABLE_ADDRESS + slot as u64 * 8, &stub.to_le_bytes())?;
    }
    for (index, import) in image.imports.iter().enumerate() {
        let stub = IMPORT_STUB_ADDRESS + index as u64 * 16;
        uc.mem_write(
            image.image_base + u64::from(import.iat_rva),
            &stub.to_le_bytes(),
        )?;
    }
    uc.mem_map(IMPORT_STUB_ADDRESS, 0x10000, Prot::READ | Prot::EXEC)?;
    uc.mem_write(IMPORT_STUB_ADDRESS, &returns[..0x10000])?;
    uc.mem_map(SENTINEL_ADDRESS, PAGE, Prot::READ | Prot::EXEC)?;
    uc.mem_write(SENTINEL_ADDRESS, &[0xC3])?;
    uc.mem_write(STREAM_ADDRESS, &context.secrets.keystream)?;
    uc.mem_write(
        image.image_base + u64::from(context.secrets.global_rva),
        &STREAM_ADDRESS.to_le_bytes(),
    )?;
    Ok(())
}

fn jni_slot(address: u64) -> Option<usize> {
    if (STUB_ADDRESS..STUB_ADDRESS + JNI_SLOTS as u64 * 16).contains(&address)
        && (address - STUB_ADDRESS) % 16 == 0
    {
        usize::try_from((address - STUB_ADDRESS) / 16).ok()
    } else {
        None
    }
}

fn import_slot(address: u64) -> Option<usize> {
    if (IMPORT_STUB_ADDRESS..IMPORT_STUB_ADDRESS + 0x10000).contains(&address)
        && (address - IMPORT_STUB_ADDRESS) % 16 == 0
    {
        usize::try_from((address - IMPORT_STUB_ADDRESS) / 16).ok()
    } else {
        None
    }
}

fn parameter_kinds(descriptor: &str) -> Vec<u8> {
    let bytes = descriptor.as_bytes();
    let mut index = if bytes.first() == Some(&b'(') {
        1
    } else {
        bytes.len()
    };
    let mut kinds = Vec::new();
    while index < bytes.len() && bytes[index] != b')' {
        let kind = bytes[index];
        kinds.push(kind);
        while index < bytes.len() && bytes[index] == b'[' {
            index += 1;
        }
        if index < bytes.len() && bytes[index] == b'L' {
            while index < bytes.len() && bytes[index] != b';' {
                index += 1;
            }
            index = (index + 1).min(bytes.len());
        } else {
            index += 1;
        }
    }
    kinds
}

fn set_result(
    uc: &mut Unicorn<'_, ()>,
    state: &mut TraceState<'_>,
    register: Register,
    value: Value,
    handle: Option<u64>,
) {
    if register == Register::RAX {
        if let Some(handle) = handle {
            let _ = uc.reg_write(RegisterX86::RAX, handle);
        }
        state.registers.insert(Register::RAX, value);
    }
}

fn set_integer_result(
    uc: &mut Unicorn<'_, ()>,
    state: &mut TraceState<'_>,
    value: i64,
    expression: Value,
) {
    let _ = uc.reg_write(RegisterX86::RAX, value as u64);
    state.registers.insert(Register::RAX, expression);
}

fn read_register(uc: &Unicorn<'_, ()>, register: RegisterX86) -> u64 {
    uc.reg_read(register).unwrap_or(0)
}

fn u64_to_option(value: Option<u64>) -> Option<u64> {
    value
}

fn register_id(register: Register) -> RegisterX86 {
    match register {
        Register::RAX => RegisterX86::RAX,
        Register::RBX => RegisterX86::RBX,
        Register::RCX => RegisterX86::RCX,
        Register::RDX => RegisterX86::RDX,
        Register::RSI => RegisterX86::RSI,
        Register::RDI => RegisterX86::RDI,
        Register::RSP => RegisterX86::RSP,
        Register::RBP => RegisterX86::RBP,
        Register::R8 => RegisterX86::R8,
        Register::R9 => RegisterX86::R9,
        Register::R10 => RegisterX86::R10,
        Register::R11 => RegisterX86::R11,
        Register::R12 => RegisterX86::R12,
        Register::R13 => RegisterX86::R13,
        Register::R14 => RegisterX86::R14,
        Register::R15 => RegisterX86::R15,
        Register::XMM0 => RegisterX86::XMM0,
        _ => RegisterX86::RAX,
    }
}

fn operator(mnemonic: Mnemonic) -> &'static str {
    match mnemonic {
        Mnemonic::Add | Mnemonic::Addsd | Mnemonic::Addss => "+",
        Mnemonic::Sub | Mnemonic::Subsd | Mnemonic::Subss => "-",
        Mnemonic::Imul | Mnemonic::Mulsd | Mnemonic::Mulss => "*",
        Mnemonic::Xor => "^",
        Mnemonic::And => "&",
        Mnemonic::Or => "|",
        Mnemonic::Shl => "<<",
        Mnemonic::Shr => ">>>",
        Mnemonic::Sar => ">>",
        _ => "+",
    }
}

fn conditional_operator(mnemonic: Mnemonic) -> &'static str {
    match mnemonic {
        Mnemonic::Je => "==",
        Mnemonic::Jne => "!=",
        Mnemonic::Jg => ">",
        Mnemonic::Jge => ">=",
        Mnemonic::Jl => "<",
        Mnemonic::Jle => "<=",
        Mnemonic::Ja => ">",
        Mnemonic::Jae => ">=",
        Mnemonic::Jb => "<",
        Mnemonic::Jbe => "<=",
        _ => "!=",
    }
}

fn is_conditional_jump(instruction: &Instruction) -> bool {
    matches!(
        instruction.mnemonic(),
        Mnemonic::Je
            | Mnemonic::Jne
            | Mnemonic::Jg
            | Mnemonic::Jge
            | Mnemonic::Jl
            | Mnemonic::Jle
            | Mnemonic::Ja
            | Mnemonic::Jae
            | Mnemonic::Jb
            | Mnemonic::Jbe
    )
}

fn actual_condition(uc: &Unicorn<'_, ()>, mnemonic: Mnemonic) -> bool {
    let flags = uc.reg_read(RegisterX86::EFLAGS).unwrap_or(0);
    let zf = flags & 0x40 != 0;
    let sf = flags & 0x80 != 0;
    let of = flags & 0x800 != 0;
    let cf = flags & 1 != 0;
    match mnemonic {
        Mnemonic::Je => zf,
        Mnemonic::Jne => !zf,
        Mnemonic::Jg => !zf && sf == of,
        Mnemonic::Jge => sf == of,
        Mnemonic::Jl => sf != of,
        Mnemonic::Jle => zf || sf != of,
        Mnemonic::Ja => !cf && !zf,
        Mnemonic::Jae => !cf,
        Mnemonic::Jb => cf,
        Mnemonic::Jbe => cf || zf,
        _ => false,
    }
}

fn force_condition(uc: &mut Unicorn<'_, ()>, mnemonic: Mnemonic, desired: bool) -> bool {
    let flags = uc.reg_read(RegisterX86::EFLAGS).unwrap_or(0);
    let new_flags = match mnemonic {
        Mnemonic::Je if desired => flags | 0x40,
        Mnemonic::Je => flags & !0x40,
        Mnemonic::Jne if desired => flags & !0x40,
        Mnemonic::Jne => flags | 0x40,
        Mnemonic::Jg | Mnemonic::Jge if desired => (flags & !0x40 & !1 & !0x800) | 0x80,
        Mnemonic::Jg | Mnemonic::Jge => (flags & !0x80) | 1 | 0x800,
        Mnemonic::Jl | Mnemonic::Jle if desired => (flags & !0x80) | 1 | 0x800,
        Mnemonic::Jl | Mnemonic::Jle => (flags & !0x40 & !1 & !0x800) | 0x80,
        Mnemonic::Ja | Mnemonic::Jae if desired => flags & !1 & !0x40,
        Mnemonic::Ja | Mnemonic::Jae => flags | 1,
        Mnemonic::Jb | Mnemonic::Jbe if desired => flags | 1,
        Mnemonic::Jb | Mnemonic::Jbe => flags & !1 & !0x40,
        _ => return false,
    };
    uc.reg_write(RegisterX86::EFLAGS, new_flags).is_ok()
}

fn quote_java(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            _ => output.push(character),
        }
    }
    output.push('"');
    output
}

fn render_u64(value: u64) -> String {
    if value <= u32::MAX as u64 {
        format!("{}", (value as u32) as i32)
    } else if value <= i64::MAX as u64 {
        format!("{}", value as i64)
    } else {
        format!("{value}")
    }
}

fn compare_prefix(left: &str, right: &str, count: usize) -> i64 {
    for index in 0..count {
        let l = left.as_bytes().get(index).copied().unwrap_or(0);
        let r = right.as_bytes().get(index).copied().unwrap_or(0);
        if l != r {
            return i64::from(l) - i64::from(r);
        }
    }
    0
}

fn align_up(value: u64, alignment: u64) -> u64 {
    value.div_ceil(alignment) * alignment
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_kinds_parse_descriptors() {
        assert_eq!(
            parameter_kinds("(ILjava/lang/String;[[B)V"),
            [b'I', b'L', b'[']
        );
    }

    #[test]
    fn java_strings_are_escaped() {
        assert_eq!(quote_java("a\\b\"c"), "\"a\\\\b\\\"c\"");
    }
}

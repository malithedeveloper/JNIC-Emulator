#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisMode {
    Static,
    Dynamic,
}

#[derive(Debug, Clone, Copy)]
pub struct DynamicConfig {
    pub max_instructions_per_scenario: usize,
    pub max_scenarios_per_method: usize,
    pub timeout_micros_per_scenario: u64,
    pub max_statements_per_method: usize,
}

impl Default for DynamicConfig {
    fn default() -> Self {
        Self {
            max_instructions_per_scenario: 2_000_000,
            max_scenarios_per_method: 16,
            timeout_micros_per_scenario: 500_000,
            max_statements_per_method: 20_000,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DynamicMethodAnalysis {
    pub attempted: bool,
    pub completed: bool,
    pub stop_reason: String,
    pub instructions: usize,
    pub scenarios: usize,
    pub jni_events: Vec<String>,
    pub java_body: Vec<String>,
    pub diagnostics: Vec<String>,
}

impl DynamicMethodAnalysis {
    #[must_use]
    pub fn unavailable(reason: &str) -> Self {
        Self {
            attempted: false,
            stop_reason: reason.to_owned(),
            ..Self::default()
        }
    }
}

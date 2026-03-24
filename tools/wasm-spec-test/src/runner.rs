use crate::wasm::decoder::{ExportKind, FuncTypeDef, GlobalDef, ImportKind, WasmModule};
use crate::wasm::runtime::{ExecResult, WasmInstance};
use crate::wasm::types::{RuntimeClass, ValType, Value, V128, WasmError};
use anyhow::{Context, Result, anyhow, bail};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use wast::{
    QuoteWat, WastDirective, WastExecute, WastRet, Wat,
    core::{AbstractHeapType, HeapType, NanPattern, V128Pattern, WastArgCore, WastRetCore},
    lexer::Lexer,
    parser::ParseBuffer,
    token::{F32, F64, Id},
};

const DEFAULT_FUEL: u64 = 1_000_000_000;
const SPECTEST_MODULE: &str = "spectest";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileStatus {
    Pass,
    Fail,
    Skip,
}

#[derive(Debug, Clone)]
pub struct FailureDetail {
    pub line: usize,
    pub kind: &'static str,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct FileReport {
    pub path: PathBuf,
    pub total_assertions: usize,
    pub passed_assertions: usize,
    pub skipped_assertions: usize,
    pub failures: Vec<FailureDetail>,
    pub skipped_reasons: Vec<String>,
}

impl FileReport {
    pub fn status(&self) -> FileStatus {
        if !self.failures.is_empty() {
            FileStatus::Fail
        } else if self.passed_assertions == 0 && self.skipped_assertions > 0 {
            FileStatus::Skip
        } else {
            FileStatus::Pass
        }
    }
}

#[derive(Debug)]
struct DirectiveError {
    kind: &'static str,
    message: String,
    counts_as_assertion: bool,
}

impl DirectiveError {
    fn directive(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            counts_as_assertion: false,
        }
    }

    fn assertion(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            counts_as_assertion: true,
        }
    }
}

#[derive(Debug)]
enum DirectiveOutcome {
    NonAssertion,
    AssertionPassed,
    AssertionSkipped(String),
}

#[derive(Debug, Clone)]
struct RunnerError {
    kind: &'static str,
    message: String,
}

impl RunnerError {
    fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    fn trap(err: WasmError) -> Self {
        Self::new("trap", trap_message(&err))
    }
}

type RunnerResult<T> = std::result::Result<T, RunnerError>;

struct InstanceRecord {
    instance: WasmInstance,
}

type InstanceHandle = Rc<RefCell<InstanceRecord>>;

pub struct WastRunner {
    verbose: bool,
    module_definitions: HashMap<String, Vec<u8>>,
    instances: HashMap<String, InstanceHandle>,
    current: Option<InstanceHandle>,
    anonymous_instances: usize,
}

impl WastRunner {
    pub fn new(verbose: bool) -> Self {
        Self {
            verbose,
            module_definitions: HashMap::new(),
            instances: HashMap::new(),
            current: None,
            anonymous_instances: 0,
        }
    }

    pub fn run_file(path: &Path, verbose: bool) -> Result<FileReport> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let mut lexer = Lexer::new(&text);
        lexer.allow_confusing_unicode(true);
        let buffer = ParseBuffer::new_with_lexer(lexer)
            .map_err(|err| annotate_wast_error(err, path, &text))?;
        let wast = wast::parser::parse::<wast::Wast<'_>>(&buffer)
            .map_err(|err| annotate_wast_error(err, path, &text))?;

        let mut runner = Self::new(verbose);
        let mut report = FileReport {
            path: path.to_path_buf(),
            total_assertions: 0,
            passed_assertions: 0,
            skipped_assertions: 0,
            failures: Vec::new(),
            skipped_reasons: Vec::new(),
        };

        for directive in wast.directives {
            let span = directive.span();
            let (line, _column) = span.linecol_in(&text);
            let line = line + 1;
            match runner.process_directive(directive) {
                Ok(DirectiveOutcome::NonAssertion) => {}
                Ok(DirectiveOutcome::AssertionPassed) => {
                    report.total_assertions += 1;
                    report.passed_assertions += 1;
                }
                Ok(DirectiveOutcome::AssertionSkipped(reason)) => {
                    report.total_assertions += 1;
                    report.skipped_assertions += 1;
                    report
                        .skipped_reasons
                        .push(format!("line {line}: {reason}"));
                }
                Err(error) => {
                    if error.counts_as_assertion {
                        report.total_assertions += 1;
                    }
                    report.failures.push(FailureDetail {
                        line,
                        kind: error.kind,
                        message: error.message,
                    });
                }
            }
        }

        Ok(report)
    }

    fn process_directive(&mut self, directive: WastDirective<'_>) -> std::result::Result<DirectiveOutcome, DirectiveError> {
        match directive {
            WastDirective::Module(mut module) => {
                let (name, bytes) = self.module_bytes(&mut module).map_err(|err| {
                    DirectiveError::directive("module", format!("compile failed: {}", err.message))
                })?;
                self.instantiate_module_bytes(name.as_deref(), &bytes)
                    .map_err(|err| {
                        DirectiveError::directive("module", format!("instantiate failed: {}", err.message))
                    })?;
                Ok(DirectiveOutcome::NonAssertion)
            }
            WastDirective::ModuleDefinition(mut module) => {
                let (name, bytes) = self.module_bytes(&mut module).map_err(|err| {
                    DirectiveError::directive(
                        "module_definition",
                        format!("compile failed: {}", err.message),
                    )
                })?;
                if let Some(name) = name {
                    self.module_definitions.insert(name, bytes);
                }
                Ok(DirectiveOutcome::NonAssertion)
            }
            WastDirective::ModuleInstance { instance, module, .. } => {
                let Some(module) = module else {
                    return Err(DirectiveError::directive(
                        "module_instance",
                        "unnamed module definitions are not supported",
                    ));
                };
                let bytes = self
                    .module_definitions
                    .get(module.name())
                    .cloned()
                    .ok_or_else(|| {
                        DirectiveError::directive(
                            "module_instance",
                            format!("missing module definition `{}`", module.name()),
                        )
                    })?;
                self.instantiate_module_bytes(instance.map(|id| id.name()), &bytes)
                    .map_err(|err| {
                        DirectiveError::directive(
                            "module_instance",
                            format!("instantiate failed: {}", err.message),
                        )
                    })?;
                Ok(DirectiveOutcome::NonAssertion)
            }
            WastDirective::Register { name, module, .. } => {
                let handle = self.get_instance_handle(module).map_err(|err| {
                    DirectiveError::directive("register", err.message)
                })?;
                self.instances.insert(name.to_string(), handle);
                Ok(DirectiveOutcome::NonAssertion)
            }
            WastDirective::Invoke(invoke) => {
                self.invoke(invoke).map_err(|err| {
                    DirectiveError::directive("invoke", err.message)
                })?;
                Ok(DirectiveOutcome::NonAssertion)
            }
            WastDirective::AssertMalformed { mut module, message, .. } => {
                let outcome = module
                    .encode()
                    .map_err(|err| RunnerError::new("decode", err.to_string()))
                    .and_then(|bytes| self.decode_module(&bytes));
                match outcome {
                    Ok(_) => Err(DirectiveError::assertion(
                        "assert_malformed",
                        format!("module unexpectedly decoded successfully; expected `{message}`"),
                    )),
                    Err(_) => Ok(DirectiveOutcome::AssertionPassed),
                }
            }
            WastDirective::AssertInvalid { mut module, message, .. } => {
                let outcome = self.compile_module(&mut module);
                match outcome {
                    Ok(_) => Err(DirectiveError::assertion(
                        "assert_invalid",
                        format!("module unexpectedly validated successfully; expected `{message}`"),
                    )),
                    Err(_) => Ok(DirectiveOutcome::AssertionPassed),
                }
            }
            WastDirective::AssertUnlinkable { module, message, .. } => {
                let mut quoted = QuoteWat::Wat(module);
                let (name, bytes) = self.module_bytes(&mut quoted).map_err(|err| {
                    DirectiveError::assertion("assert_unlinkable", err.message)
                })?;
                match self.instantiate_module_bytes(name.as_deref(), &bytes) {
                    Ok(_) => Err(DirectiveError::assertion(
                        "assert_unlinkable",
                        format!("module unexpectedly linked successfully; expected `{message}`"),
                    )),
                    Err(_) => Ok(DirectiveOutcome::AssertionPassed),
                }
            }
            WastDirective::AssertTrap { exec, message, .. } => {
                match self.execute(exec) {
                    Ok(values) => Err(DirectiveError::assertion(
                        "assert_trap",
                        format!("expected trap `{message}`, got {:?}", values),
                    )),
                    Err(err) => {
                        self.assert_message("assert_trap", &err, message)?;
                        Ok(DirectiveOutcome::AssertionPassed)
                    }
                }
            }
            WastDirective::AssertReturn { exec, results, .. } => {
                let actual = self.execute(exec).map_err(|err| {
                    DirectiveError::assertion("assert_return", err.message)
                })?;
                self.assert_results(&actual, &results)?;
                Ok(DirectiveOutcome::AssertionPassed)
            }
            WastDirective::AssertExhaustion { call, message, .. } => {
                match self.invoke(call) {
                    Ok(values) => Err(DirectiveError::assertion(
                        "assert_exhaustion",
                        format!("expected exhaustion `{message}`, got {:?}", values),
                    )),
                    Err(err) => {
                        self.assert_message("assert_exhaustion", &err, message)?;
                        Ok(DirectiveOutcome::AssertionPassed)
                    }
                }
            }
            WastDirective::AssertException { .. }
            | WastDirective::AssertSuspension { .. }
            | WastDirective::Thread(..)
            | WastDirective::Wait { .. } => Ok(DirectiveOutcome::AssertionSkipped(
                "directive is not supported by the ATOS host-side runner".to_string(),
            )),
        }
    }

    fn module_bytes(&mut self, module: &mut QuoteWat<'_>) -> RunnerResult<(Option<String>, Vec<u8>)> {
        if !is_core_module(module) {
            return Err(RunnerError::new(
                "unsupported",
                "component model directives are not supported",
            ));
        }
        let name = module.name().map(|id| id.name().to_string());
        let bytes = module
            .encode()
            .map_err(|err| RunnerError::new("decode", err.to_string()))?;
        Ok((name, bytes))
    }

    fn compile_module(&mut self, module: &mut QuoteWat<'_>) -> RunnerResult<(Option<String>, WasmModule)> {
        let (name, bytes) = self.module_bytes(module)?;
        let decoded = self.decode_module(&bytes)?;
        Ok((name, decoded))
    }

    fn decode_module(&self, bytes: &[u8]) -> RunnerResult<WasmModule> {
        let module = crate::wasm::decoder::decode(bytes)
            .map_err(|err| RunnerError::new("decode", format!("{err:?}")))?;
        crate::wasm::validator::validate(&module)
            .map_err(|err| RunnerError::new("validation", format!("{err:?}")))?;
        Ok(module)
    }

    fn instantiate_module_bytes(&mut self, name: Option<&str>, bytes: &[u8]) -> RunnerResult<InstanceHandle> {
        let mut module = self.decode_module(bytes)?;
        self.inject_imported_globals(&mut module)?;
        self.ensure_linkable_function_imports(&module)?;

        if name.is_none() {
            self.anonymous_instances += 1;
        }
        let handle = Rc::new(RefCell::new(InstanceRecord {
            instance: WasmInstance::with_class(module, DEFAULT_FUEL, RuntimeClass::BestEffort),
        }));

        let inserted_name = name.map(str::to_string);
        if let Some(name) = &inserted_name {
            self.instances.insert(name.clone(), handle.clone());
        }

        if let Err(err) = self.run_start(&handle) {
            if let Some(name) = &inserted_name {
                self.instances.remove(name);
            }
            return Err(err);
        }

        self.current = Some(handle.clone());
        Ok(handle)
    }

    fn run_start(&mut self, handle: &InstanceHandle) -> RunnerResult<()> {
        let mut record = handle.try_borrow_mut().map_err(|_| {
            RunnerError::new("link", "re-entrant instance execution is not supported")
        })?;
        record.instance.stack_ptr = 0;
        let mut result = record.instance.run_start();
        loop {
            match result {
                ExecResult::Ok | ExecResult::Returned(_) => return Ok(()),
                ExecResult::OutOfFuel => {
                    return Err(RunnerError::new("trap", "out of fuel while running start"));
                }
                ExecResult::Trap(err) => return Err(RunnerError::trap(err)),
                ExecResult::HostCall(import_idx, args, arg_count) => {
                    let ret = self.dispatch_host_call(
                        &mut record.instance,
                        import_idx,
                        &args[..arg_count as usize],
                    )?;
                    result = record.instance.resume(ret);
                }
            }
        }
    }

    fn execute(&mut self, exec: WastExecute<'_>) -> RunnerResult<Vec<Value>> {
        match exec {
            WastExecute::Invoke(invoke) => self.invoke(invoke),
            WastExecute::Wat(Wat::Module(module)) => {
                let mut quoted = QuoteWat::Wat(Wat::Module(module));
                let (_name, bytes) = self.module_bytes(&mut quoted)?;
                self.instantiate_module_bytes(None, &bytes)?;
                Ok(Vec::new())
            }
            WastExecute::Get { module, global, .. } => {
                let value = self.get_global(module, global)?;
                Ok(vec![value])
            }
            _ => Err(RunnerError::new(
                "unsupported",
                "execution directive is not supported by the ATOS runner",
            )),
        }
    }

    fn invoke(&mut self, invoke: wast::WastInvoke<'_>) -> RunnerResult<Vec<Value>> {
        let handle = self.get_instance_handle(invoke.module)?;
        let args = self.values_from_args(&invoke.args)?;
        let func_idx = {
            let record = handle.borrow();
            record
                .instance
                .module
                .find_export_func(invoke.name.as_bytes())
                .ok_or_else(|| {
                    RunnerError::new(
                        "link",
                        format!("missing exported function `{}`", invoke.name),
                    )
                })?
        };
        self.execute_call(&handle, func_idx, &args)
    }

    fn execute_call(&mut self, handle: &InstanceHandle, func_idx: u32, args: &[Value]) -> RunnerResult<Vec<Value>> {
        let mut record = handle.try_borrow_mut().map_err(|_| {
            RunnerError::new("link", "re-entrant instance execution is not supported")
        })?;
        record.instance.stack_ptr = 0;
        let mut result = record.instance.call_func(func_idx, args);
        loop {
            match result {
                ExecResult::Ok | ExecResult::Returned(_) => {
                    return Ok(record.instance.stack[..record.instance.stack_ptr].to_vec());
                }
                ExecResult::OutOfFuel => return Err(RunnerError::new("trap", "out of fuel")),
                ExecResult::Trap(err) => return Err(RunnerError::trap(err)),
                ExecResult::HostCall(import_idx, values, arg_count) => {
                    let ret = self.dispatch_host_call(
                        &mut record.instance,
                        import_idx,
                        &values[..arg_count as usize],
                    )?;
                    result = record.instance.resume(ret);
                }
            }
        }
    }

    fn get_global(&self, module: Option<Id<'_>>, global_name: &str) -> RunnerResult<Value> {
        let handle = self.get_instance_handle(module)?;
        let record = handle.borrow();
        let idx = exported_global_index(&record.instance.module, global_name).ok_or_else(|| {
            RunnerError::new("link", format!("missing exported global `{global_name}`"))
        })?;
        record
            .instance
            .globals
            .get(idx as usize)
            .copied()
            .ok_or_else(|| RunnerError::new("link", "global index out of bounds"))
    }

    fn get_instance_handle(&self, module: Option<Id<'_>>) -> RunnerResult<InstanceHandle> {
        match module {
            Some(name) => self
                .instances
                .get(name.name())
                .cloned()
                .ok_or_else(|| RunnerError::new("link", format!("unknown instance `{}`", name.name()))),
            None => self
                .current
                .clone()
                .ok_or_else(|| RunnerError::new("link", "no current instance available")),
        }
    }

    fn values_from_args(&self, args: &[wast::WastArg<'_>]) -> RunnerResult<Vec<Value>> {
        let mut values = Vec::with_capacity(args.len());
        for arg in args {
            match arg {
                wast::WastArg::Core(arg) => values.push(self.value_from_arg(arg)?),
                _ => {
                    return Err(RunnerError::new(
                        "unsupported",
                        "component-model arguments are not supported",
                    ));
                }
            }
        }
        Ok(values)
    }

    fn value_from_arg(&self, arg: &WastArgCore<'_>) -> RunnerResult<Value> {
        match arg {
            WastArgCore::I32(v) => Ok(Value::I32(*v)),
            WastArgCore::I64(v) => Ok(Value::I64(*v)),
            WastArgCore::F32(v) => Ok(Value::F32(f32::from_bits(v.bits))),
            WastArgCore::F64(v) => Ok(Value::F64(f64::from_bits(v.bits))),
            WastArgCore::V128(v) => Ok(Value::V128(V128(v.to_le_bytes()))),
            WastArgCore::RefNull(_) => Ok(Value::I32(-1)), // null ref sentinel
            WastArgCore::RefExtern(v) => Ok(Value::I32(*v as i32)),
            WastArgCore::RefHost(v) => Ok(Value::I32(*v as i32)),
        }
    }

    fn inject_imported_globals(&self, module: &mut WasmModule) -> RunnerResult<()> {
        let mut imported = Vec::new();
        for import in &module.imports {
            let ImportKind::Global(val_type_byte, mutable) = import.kind else {
                continue;
            };
            let module_name = bytes_to_string(module.get_name(import.module_name_offset, import.module_name_len));
            let field_name = bytes_to_string(module.get_name(import.field_name_offset, import.field_name_len));
            let value = if module_name == SPECTEST_MODULE {
                spectest_global(&field_name).ok_or_else(|| {
                    RunnerError::new(
                        "link",
                        format!("unknown spectest global `{field_name}`"),
                    )
                })?
            } else {
                let handle = self.instances.get(&module_name).ok_or_else(|| {
                    RunnerError::new(
                        "link",
                        format!("unknown import module `{module_name}` for global `{field_name}`"),
                    )
                })?;
                let record = handle.borrow();
                let idx = exported_global_index(&record.instance.module, &field_name).ok_or_else(|| {
                    RunnerError::new(
                        "link",
                        format!("module `{module_name}` does not export global `{field_name}`"),
                    )
                })?;
                record
                    .instance
                    .globals
                    .get(idx as usize)
                    .copied()
                    .ok_or_else(|| RunnerError::new("link", "global export index out of bounds"))?
            };
            let val_type = decode_valtype_byte(val_type_byte).ok_or_else(|| {
                RunnerError::new("link", format!("unsupported imported global type 0x{val_type_byte:02x}"))
            })?;
            if !value_matches_type(value, val_type) {
                return Err(RunnerError::new(
                    "link",
                    format!(
                        "imported global `{module_name}::{field_name}` type mismatch; expected {:?}, got {:?}",
                        val_type, value
                    ),
                ));
            }
            imported.push(GlobalDef {
                val_type,
                mutable,
                init_value: value,
            });
        }

        if !imported.is_empty() {
            let mut globals = imported;
            globals.extend(module.globals.iter().cloned());
            module.globals = globals;
        }
        Ok(())
    }

    fn ensure_linkable_function_imports(&self, module: &WasmModule) -> RunnerResult<()> {
        let mut func_idx = 0u32;
        for import in &module.imports {
            // Skip non-function imports (table, memory, global handled elsewhere)
            match import.kind {
                ImportKind::Func(_) => {}
                _ => continue,
            }
            let module_name = bytes_to_string(module.get_name(import.module_name_offset, import.module_name_len));
            let field_name = bytes_to_string(module.get_name(import.field_name_offset, import.field_name_len));
            let signature = function_type(module, func_idx).ok_or_else(|| {
                RunnerError::new("link", format!("missing function type for import `{module_name}::{field_name}`"))
            })?;

            if signature.result_count > 1 {
                return Err(RunnerError::new(
                    "link",
                    format!(
                        "imported function `{module_name}::{field_name}` uses {} results; ATOS host-call ABI supports at most one",
                        signature.result_count
                    ),
                ));
            }

            if module_name == "atos" {
                let host_func = crate::wasm::host::resolve_import(module, func_idx);
                if matches!(host_func, crate::wasm::host::HostFunc::Unknown) {
                    return Err(RunnerError::new(
                        "link",
                        format!("unknown ATOS host function `{field_name}`"),
                    ));
                }
            } else if module_name == SPECTEST_MODULE {
                ensure_spectest_function(&field_name)?;
            } else if let Some(handle) = self.instances.get(&module_name) {
                let record = handle.borrow();
                let target_idx = record
                    .instance
                    .module
                    .find_export_func(field_name.as_bytes())
                    .ok_or_else(|| {
                        RunnerError::new(
                            "link",
                            format!("module `{module_name}` does not export function `{field_name}`"),
                        )
                    })?;
                let target_ty = function_type(&record.instance.module, target_idx).ok_or_else(|| {
                    RunnerError::new(
                        "link",
                        format!("missing function type for `{module_name}::{field_name}`"),
                    )
                })?;
                if target_ty.param_count != signature.param_count || target_ty.result_count != signature.result_count {
                    return Err(RunnerError::new(
                        "link",
                        format!(
                            "imported function `{module_name}::{field_name}` signature mismatch; expected {} params/{} results, got {} params/{} results",
                            signature.param_count,
                            signature.result_count,
                            target_ty.param_count,
                            target_ty.result_count
                        ),
                    ));
                }
            } else {
                return Err(RunnerError::new(
                    "link",
                    format!("unknown import module `{module_name}`"),
                ));
            }

            func_idx = func_idx.saturating_add(1);
        }
        Ok(())
    }

    fn dispatch_host_call(
        &mut self,
        instance: &mut WasmInstance,
        import_idx: u32,
        args: &[Value],
    ) -> RunnerResult<Option<Value>> {
        let import = nth_function_import(&instance.module, import_idx).ok_or_else(|| {
            RunnerError::new("link", format!("unknown function import index {import_idx}"))
        })?;
        let module_name = bytes_to_string(instance.module.get_name(
            import.module_name_offset,
            import.module_name_len,
        ));
        let field_name = bytes_to_string(instance.module.get_name(
            import.field_name_offset,
            import.field_name_len,
        ));

        if module_name == "atos" {
            return crate::wasm::host::handle_host_call(instance, import_idx, args, args.len() as u8)
                .map_err(RunnerError::trap);
        }

        if module_name == SPECTEST_MODULE {
            return dispatch_spectest(self.verbose, &field_name, args);
        }

        let handle = self.instances.get(&module_name).cloned().ok_or_else(|| {
            RunnerError::new(
                "link",
                format!("unknown import module `{module_name}`"),
            )
        })?;
        let target_idx = {
            let record = handle.borrow();
            record
                .instance
                .module
                .find_export_func(field_name.as_bytes())
                .ok_or_else(|| {
                    RunnerError::new(
                        "link",
                        format!("module `{module_name}` does not export function `{field_name}`"),
                    )
                })?
        };
        let results = self.execute_call(&handle, target_idx, args)?;
        match results.len() {
            0 => Ok(None),
            1 => Ok(Some(results[0])),
            len => Err(RunnerError::new(
                "link",
                format!(
                    "imported function `{module_name}::{field_name}` returned {len} values; ATOS host-call ABI supports at most one",
                ),
            )),
        }
    }

    fn assert_message(
        &self,
        kind: &'static str,
        err: &RunnerError,
        expected: &str,
    ) -> std::result::Result<(), DirectiveError> {
        if err.message.contains(expected) {
            Ok(())
        } else {
            Err(DirectiveError::assertion(
                kind,
                format!("expected message `{expected}`, got `{}` ({})", err.message, err.kind),
            ))
        }
    }

    fn assert_results(
        &self,
        actual: &[Value],
        expected: &[WastRet<'_>],
    ) -> std::result::Result<(), DirectiveError> {
        if actual.len() != expected.len() {
            return Err(DirectiveError::assertion(
                "assert_return",
                format!(
                    "result count mismatch; expected {}, got {}",
                    expected.len(),
                    actual.len()
                ),
            ));
        }

        for (actual, expected) in actual.iter().zip(expected) {
            self.assert_result(actual, expected)?;
        }
        Ok(())
    }

    fn assert_result(
        &self,
        actual: &Value,
        expected: &WastRet<'_>,
    ) -> std::result::Result<(), DirectiveError> {
        match expected {
            WastRet::Core(expected) => self.assert_result_core(actual, expected),
            _ => Err(DirectiveError::assertion(
                "assert_return",
                "component-model results are not supported",
            )),
        }
    }

    fn assert_result_core(
        &self,
        actual: &Value,
        expected: &WastRetCore<'_>,
    ) -> std::result::Result<(), DirectiveError> {
        match expected {
            WastRetCore::Either(options) => {
                for option in options {
                    if self.assert_result_core(actual, option).is_ok() {
                        return Ok(());
                    }
                }
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!("none of the `either` alternatives matched actual value {actual:?}"),
                ))
            }
            WastRetCore::I32(expected) => match actual {
                Value::I32(value) if value == expected => Ok(()),
                _ => Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected i32 {expected}, got {actual:?}"),
                )),
            },
            WastRetCore::I64(expected) => match actual {
                Value::I64(value) if value == expected => Ok(()),
                _ => Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected i64 {expected}, got {actual:?}"),
                )),
            },
            WastRetCore::F32(expected) => match actual {
                Value::F32(value) => f32_matches(*value, expected),
                _ => Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected f32 result, got {actual:?}"),
                )),
            },
            WastRetCore::F64(expected) => match actual {
                Value::F64(value) => f64_matches(*value, expected),
                _ => Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected f64 result, got {actual:?}"),
                )),
            },
            WastRetCore::V128(expected) => match actual {
                Value::V128(value) => v128_matches(*value, expected),
                _ => Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected v128 result, got {actual:?}"),
                )),
            },
            WastRetCore::RefNull(_) => {
                // null ref: our sentinel is I32(-1)
                match actual {
                    Value::I32(-1) => Ok(()),
                    Value::I32(v) if *v < 0 => Ok(()), // any negative = null
                    _ => Err(DirectiveError::assertion(
                        "assert_return",
                        format!("expected ref.null, got {actual:?}"),
                    )),
                }
            }
            WastRetCore::RefExtern(Some(v)) => {
                match actual {
                    Value::I32(a) if *a as u32 == *v => Ok(()),
                    _ => Err(DirectiveError::assertion(
                        "assert_return",
                        format!("expected ref.extern {v}, got {actual:?}"),
                    )),
                }
            }
            WastRetCore::RefExtern(None) => {
                // ref.extern with no value = null
                match actual {
                    Value::I32(-1) => Ok(()),
                    _ => Err(DirectiveError::assertion(
                        "assert_return",
                        format!("expected ref.extern null, got {actual:?}"),
                    )),
                }
            }
            WastRetCore::RefFunc(None) => {
                // Any non-null func ref
                match actual {
                    Value::I32(v) if *v >= 0 => Ok(()),
                    _ => Err(DirectiveError::assertion(
                        "assert_return",
                        format!("expected ref.func (non-null), got {actual:?}"),
                    )),
                }
            }
            WastRetCore::RefFunc(Some(_)) => {
                // Specific func ref — just check non-null
                match actual {
                    Value::I32(v) if *v >= 0 => Ok(()),
                    _ => Err(DirectiveError::assertion(
                        "assert_return",
                        format!("expected ref.func, got {actual:?}"),
                    )),
                }
            }
            WastRetCore::RefHost(_)
            | WastRetCore::RefAny
            | WastRetCore::RefEq
            | WastRetCore::RefArray
            | WastRetCore::RefStruct
            | WastRetCore::RefI31
            | WastRetCore::RefI31Shared => Err(DirectiveError::assertion(
                "assert_return",
                "GC reference-type results are not supported by the ATOS engine",
            )),
        }
    }
}

pub fn collect_wast_files(path: &Path) -> Result<Vec<PathBuf>> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.is_file() {
        if path.extension().and_then(|ext| ext.to_str()) == Some("wast") {
            return Ok(vec![path.to_path_buf()]);
        }
        bail!("{} is not a .wast file", path.display());
    }

    let mut files = Vec::new();
    collect_wast_files_recursive(path, &mut files)
        .with_context(|| format!("failed to read directory {}", path.display()))?;
    Ok(files)
}

fn collect_wast_files_recursive(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let metadata = fs::metadata(&entry_path)?;
        if metadata.is_dir() {
            collect_wast_files_recursive(&entry_path, out)?;
        } else if entry_path.extension().and_then(|ext| ext.to_str()) == Some("wast") {
            out.push(entry_path);
        }
    }
    Ok(())
}

fn annotate_wast_error(mut err: wast::Error, path: &Path, text: &str) -> anyhow::Error {
    err.set_path(path);
    err.set_text(text);
    anyhow!(err)
}

fn is_core_module(module: &QuoteWat<'_>) -> bool {
    matches!(module, QuoteWat::Wat(Wat::Module(_)) | QuoteWat::QuoteModule(..))
}

fn bytes_to_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn nth_function_import(module: &WasmModule, func_idx: u32) -> Option<&crate::wasm::decoder::ImportDef> {
    let mut seen = 0u32;
    for import in &module.imports {
        if let ImportKind::Func(_) = import.kind {
            if seen == func_idx {
                return Some(import);
            }
            seen = seen.saturating_add(1);
        }
    }
    None
}

fn function_type(module: &WasmModule, func_idx: u32) -> Option<&FuncTypeDef> {
    if (func_idx as usize) < module.func_import_count() {
        let type_idx = module.func_import_type(func_idx)? as usize;
        return module.func_types.get(type_idx);
    }
    let local_idx = (func_idx as usize).checked_sub(module.func_import_count())?;
    let func = module.functions.get(local_idx)?;
    module.func_types.get(func.type_idx as usize)
}

fn exported_global_index(module: &WasmModule, name: &str) -> Option<u32> {
    for export in &module.exports {
        if module.get_name(export.name_offset, export.name_len) == name.as_bytes() {
            if let ExportKind::Global(idx) = export.kind {
                return Some(idx);
            }
        }
    }
    None
}

fn ensure_spectest_function(name: &str) -> RunnerResult<()> {
    match name {
        "print"
        | "print_i32"
        | "print_i64"
        | "print_f32"
        | "print_f64"
        | "print_i32_f32"
        | "print_f64_f64"
        | "print32"
        | "print64" => Ok(()),
        _ => Err(RunnerError::new(
            "link",
            format!("unknown spectest function `{name}`"),
        )),
    }
}

fn dispatch_spectest(verbose: bool, name: &str, args: &[Value]) -> RunnerResult<Option<Value>> {
    match name {
        "print" => {
            if verbose {
                println!("[spectest] print()");
            }
            Ok(None)
        }
        "print_i32" => {
            if verbose {
                println!("[spectest] print_i32({})", args.get(0).copied().unwrap_or(Value::I32(0)).as_i32());
            }
            Ok(None)
        }
        "print_i64" => {
            if verbose {
                println!("[spectest] print_i64({})", args.get(0).copied().unwrap_or(Value::I64(0)).as_i64());
            }
            Ok(None)
        }
        "print_f32" => {
            if verbose {
                println!("[spectest] print_f32({:?})", args.get(0).copied().unwrap_or(Value::F32(0.0)));
            }
            Ok(None)
        }
        "print_f64" => {
            if verbose {
                println!("[spectest] print_f64({:?})", args.get(0).copied().unwrap_or(Value::F64(0.0)));
            }
            Ok(None)
        }
        "print_i32_f32" => {
            if verbose {
                let i = args.get(0).copied().unwrap_or(Value::I32(0)).as_i32();
                let f = args.get(1).copied().unwrap_or(Value::F32(0.0)).as_f32();
                println!("[spectest] print_i32_f32({i}, {f:?})");
            }
            Ok(None)
        }
        "print_f64_f64" => {
            if verbose {
                let a = args.get(0).copied().unwrap_or(Value::F64(0.0)).as_f64();
                let b = args.get(1).copied().unwrap_or(Value::F64(0.0)).as_f64();
                println!("[spectest] print_f64_f64({a:?}, {b:?})");
            }
            Ok(None)
        }
        "print32" => {
            if verbose {
                println!("[spectest] print32({})", args.get(0).copied().unwrap_or(Value::I32(0)).as_i32());
            }
            Ok(None)
        }
        "print64" => {
            if verbose {
                println!("[spectest] print64({})", args.get(0).copied().unwrap_or(Value::I64(0)).as_i64());
            }
            Ok(None)
        }
        _ => Err(RunnerError::new(
            "link",
            format!("unknown spectest function `{name}`"),
        )),
    }
}

fn spectest_global(name: &str) -> Option<Value> {
    match name {
        "global_i32" => Some(Value::I32(666)),
        "global_i64" => Some(Value::I64(666)),
        "global_f32" => Some(Value::F32(f32::from_bits(0x4426_a666))),
        "global_f64" => Some(Value::F64(f64::from_bits(0x4084_d4cc_cccc_cccd))),
        "global_funcref" => Some(Value::I32(-1)),    // null funcref
        "global_externref" => Some(Value::I32(-1)),   // null externref
        _ => None,
    }
}

fn decode_valtype_byte(byte: u8) -> Option<ValType> {
    match byte {
        0x7F => Some(ValType::I32),
        0x7E => Some(ValType::I64),
        0x7D => Some(ValType::F32),
        0x7C => Some(ValType::F64),
        0x7B => Some(ValType::V128),
        0x70 | 0x6F => Some(ValType::I32), // funcref, externref -> I32 placeholder
        _ => None,
    }
}

fn value_matches_type(value: Value, val_type: ValType) -> bool {
    matches!(
        (value, val_type),
        (Value::I32(_), ValType::I32)
            | (Value::I64(_), ValType::I64)
            | (Value::F32(_), ValType::F32)
            | (Value::F64(_), ValType::F64)
            | (Value::V128(_), ValType::V128)
    )
}

fn trap_message(err: &WasmError) -> String {
    match err {
        WasmError::DivisionByZero => "integer divide by zero".to_string(),
        WasmError::IntegerOverflow => "integer overflow".to_string(),
        WasmError::InvalidConversionToInteger => "invalid conversion to integer".to_string(),
        WasmError::MemoryOutOfBounds => "out of bounds memory access".to_string(),
        WasmError::CallStackOverflow | WasmError::StackOverflow => {
            "call stack exhausted".to_string()
        }
        WasmError::UnreachableExecuted => "unreachable".to_string(),
        WasmError::UndefinedElement => "undefined element".to_string(),
        WasmError::UninitializedElement => "uninitialized element".to_string(),
        WasmError::IndirectCallTypeMismatch => "indirect call type mismatch".to_string(),
        WasmError::ImmutableGlobal => "global is immutable".to_string(),
        WasmError::TableIndexOutOfBounds => "out of bounds table access".to_string(),
        WasmError::FloatsDisabled => "floats disabled".to_string(),
        WasmError::UnsupportedProposal => "unsupported proposal".to_string(),
        other => format!("{other:?}"),
    }
}

fn f32_matches(actual: f32, expected: &NanPattern<F32>) -> std::result::Result<(), DirectiveError> {
    let actual_bits = actual.to_bits();
    match expected {
        NanPattern::CanonicalNan => {
            const CANONICAL_NAN: u32 = 0x7FC0_0000;
            if (actual_bits & 0x7FFF_FFFF) == CANONICAL_NAN {
                Ok(())
            } else {
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected canonical NaN, got {actual:?} (0x{actual_bits:08x})"),
                ))
            }
        }
        NanPattern::ArithmeticNan => {
            const EXPONENT_MASK: u32 = 0x7F80_0000;
            const QUIET_BIT: u32 = 0x0040_0000;
            let is_nan = (actual_bits & EXPONENT_MASK) == EXPONENT_MASK;
            let is_quiet = (actual_bits & QUIET_BIT) == QUIET_BIT;
            if is_nan && is_quiet {
                Ok(())
            } else {
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected arithmetic NaN, got {actual:?} (0x{actual_bits:08x})"),
                ))
            }
        }
        NanPattern::Value(expected) => {
            if actual_bits == expected.bits {
                Ok(())
            } else {
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!(
                        "expected {:?} (0x{:08x}), got {:?} (0x{:08x})",
                        f32::from_bits(expected.bits),
                        expected.bits,
                        actual,
                        actual_bits
                    ),
                ))
            }
        }
    }
}

fn f64_matches(actual: f64, expected: &NanPattern<F64>) -> std::result::Result<(), DirectiveError> {
    let actual_bits = actual.to_bits();
    match expected {
        NanPattern::CanonicalNan => {
            const CANONICAL_NAN: u64 = 0x7ff8_0000_0000_0000;
            if (actual_bits & 0x7fff_ffff_ffff_ffff) == CANONICAL_NAN {
                Ok(())
            } else {
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected canonical NaN, got {actual:?} (0x{actual_bits:016x})"),
                ))
            }
        }
        NanPattern::ArithmeticNan => {
            const EXPONENT_MASK: u64 = 0x7FF0_0000_0000_0000;
            const QUIET_BIT: u64 = 0x0008_0000_0000_0000;
            let is_nan = (actual_bits & EXPONENT_MASK) == EXPONENT_MASK;
            let is_quiet = (actual_bits & QUIET_BIT) == QUIET_BIT;
            if is_nan && is_quiet {
                Ok(())
            } else {
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected arithmetic NaN, got {actual:?} (0x{actual_bits:016x})"),
                ))
            }
        }
        NanPattern::Value(expected) => {
            if actual_bits == expected.bits {
                Ok(())
            } else {
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!(
                        "expected {:?} (0x{:016x}), got {:?} (0x{:016x})",
                        f64::from_bits(expected.bits),
                        expected.bits,
                        actual,
                        actual_bits
                    ),
                ))
            }
        }
    }
}

fn v128_matches(actual: V128, expected: &V128Pattern) -> std::result::Result<(), DirectiveError> {
    match expected {
        V128Pattern::I8x16(expected) => {
            let lanes = actual.as_i8x16();
            if &lanes == expected {
                Ok(())
            } else {
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected {:?}, got {:?}", expected, lanes),
                ))
            }
        }
        V128Pattern::I16x8(expected) => {
            let lanes = actual.as_i16x8();
            if &lanes == expected {
                Ok(())
            } else {
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected {:?}, got {:?}", expected, lanes),
                ))
            }
        }
        V128Pattern::I32x4(expected) => {
            let lanes = actual.as_i32x4();
            if &lanes == expected {
                Ok(())
            } else {
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected {:?}, got {:?}", expected, lanes),
                ))
            }
        }
        V128Pattern::I64x2(expected) => {
            let lanes = actual.as_i64x2();
            if &lanes == expected {
                Ok(())
            } else {
                Err(DirectiveError::assertion(
                    "assert_return",
                    format!("expected {:?}, got {:?}", expected, lanes),
                ))
            }
        }
        V128Pattern::F32x4(expected) => {
            let lanes = actual.as_f32x4();
            for (idx, expected) in expected.iter().enumerate() {
                f32_matches(lanes[idx], expected).map_err(|err| {
                    DirectiveError::assertion(
                        "assert_return",
                        format!("v128 lane {idx}: {}", err.message),
                    )
                })?;
            }
            Ok(())
        }
        V128Pattern::F64x2(expected) => {
            let lanes = actual.as_f64x2();
            for (idx, expected) in expected.iter().enumerate() {
                f64_matches(lanes[idx], expected).map_err(|err| {
                    DirectiveError::assertion(
                        "assert_return",
                        format!("v128 lane {idx}: {}", err.message),
                    )
                })?;
            }
            Ok(())
        }
    }
}

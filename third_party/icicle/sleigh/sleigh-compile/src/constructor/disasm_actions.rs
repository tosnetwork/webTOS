use std::collections::{HashMap, HashSet};

use sleigh_parse::ast;
use sleigh_runtime::{
    ContextModValue, DisasmConstantValue, Field, GlobalSetAddr, PatternExprOp, semantics::Local,
};

use crate::{
    constructor::{FieldIndex, ResolveIdent, Scope, resolve_pattern_expr},
    symbols::{Symbol, SymbolKind},
};

/// A context operation - either a context modification or a globalset.
///
/// Needed to preserve processing order for the following situation:
/// `[loopEnd=1; globalset(addr, loopEnd); loopEnd=0;]`:
/// - First, `loopEnd` is set to 1 in the local context
/// - Then, `globalset` captures the *current* value of `loopEnd` (which is 1) for `addr`
/// - Finally, `loopEnd` is reset to 0
///
/// If these operations are processed out of order, the globalset might capture the wrong value.
#[derive(Clone, Debug)]
pub(crate) enum ContextAction {
    /// Modify a context field locally
    Modify(Field, Vec<PatternExprOp<ContextModValue>>),
    /// GlobalSet: saves context value for a target address (context_field_id, address_source)
    GlobalSet(u32, GlobalSetAddr),
}

#[derive(Clone, Default)]
pub(crate) struct DisasmActions {
    /// Fields assigned to in the disassembly expression
    pub fields: Vec<(FieldIndex, Vec<PatternExprOp<DisasmConstantValue>>)>,

    /// Context operations in order (modifications and globalsets)
    pub context_actions: Vec<ContextAction>,
}

pub(crate) fn resolve(
    scope: &mut Scope,
    disasm_actions: &[ast::DisasmAction],
) -> Result<DisasmActions, String> {
    let mut section = DisasmActions::default();
    let mut assigned_fields = HashMap::new();

    for action in disasm_actions {
        match action {
            ast::DisasmAction::Assignment { ident, expr } => {
                match scope.globals.lookup(*ident) {
                    // An expression that modifies the decoder context.
                    Ok(Symbol { kind: SymbolKind::ContextField, id }) => {
                        let field = scope.globals.context_fields[id as usize].field;

                        let mut out = vec![];
                        resolve_context_expr(
                            scope,
                            expr,
                            &assigned_fields,
                            &mut HashSet::new(),
                            &mut out,
                        )?;
                        section.context_actions.push(ContextAction::Modify(field, out));
                    }

                    // An expression that sets a disassembly constant.
                    // @todo: check which symbol types are allowed to be shadowed.
                    Err(_) | Ok(Symbol { kind: SymbolKind::TokenField, .. }) => {
                        let field_id = scope.add_field(*ident, Field::i64())?;

                        let mut out = vec![];
                        resolve_pattern_expr::<DisasmConstantValue>(scope, expr, &mut out)?;
                        section.fields.push((field_id, out));

                        scope.mapping.insert(*ident, Local::Field(field_id));
                        assigned_fields.insert(*ident, expr.clone());
                    }

                    Ok(Symbol { kind, .. }) => {
                        return Err(format!(
                            "{:?}<{}> is not allowed in a disassembly action expression",
                            kind,
                            scope.debug(ident)
                        ));
                    }
                }
            }
            ast::DisasmAction::GlobalSet { addr_sym, context_sym } => {
                let context_id =
                    scope.globals.lookup_kind(*context_sym, SymbolKind::ContextField)?;

                let resolved = ContextModValue::resolve_ident(scope, *addr_sym)?;
                let addr = match resolved {
                    ContextModValue::InstStart => GlobalSetAddr::InstStart,
                    ContextModValue::InstNext => GlobalSetAddr::InstNext,
                    ContextModValue::Subtable(idx) => GlobalSetAddr::Subtable(idx),
                    _ => {
                        return Err(format!(
                            "globalset address must be inst_start, inst_next, or a subtable, got: {}",
                            scope.debug(addr_sym)
                        ));
                    }
                };

                section.context_actions.push(ContextAction::GlobalSet(context_id, addr));
            }
        }
    }

    Ok(section)
}

/// Resolve a decoder-context expression while preserving the ordering of the
/// disassembly actions that precede it.
///
/// SLEIGH permits a local disassembly value to be assigned and then copied to
/// a context field in the same action block, for example
/// `[ scale = 6; address_scale = scale; ]`. These context writes must happen
/// while the constructor is decoded, before its child tables are selected.
/// Consequently the earlier local expression has to be inlined here; treating
/// an unbacked `Local::Field` as a decoder-context field reads unrelated bits
/// from the context register.
fn resolve_context_expr(
    scope: &Scope,
    expr: &ast::PatternExpr,
    assigned_fields: &HashMap<ast::Ident, ast::PatternExpr>,
    visiting: &mut HashSet<ast::Ident>,
    out: &mut Vec<PatternExprOp<ContextModValue>>,
) -> Result<(), String> {
    let op = match expr {
        ast::PatternExpr::Ident(ident) => {
            if let Some(assigned) = assigned_fields.get(ident) {
                if !visiting.insert(*ident) {
                    return Err(format!(
                        "cyclic disassembly assignment used by context expression: {}",
                        scope.debug(ident)
                    ));
                }
                resolve_context_expr(scope, assigned, assigned_fields, visiting, out)?;
                visiting.remove(ident);
                return Ok(());
            }
            PatternExprOp::Value(ContextModValue::resolve_ident(scope, *ident)?)
        }
        ast::PatternExpr::Integer(value) => PatternExprOp::Constant(*value),
        ast::PatternExpr::Op(lhs, op, rhs) => {
            resolve_context_expr(scope, lhs, assigned_fields, visiting, out)?;
            resolve_context_expr(scope, rhs, assigned_fields, visiting, out)?;
            PatternExprOp::Op(*op)
        }
        ast::PatternExpr::Not(inner) => {
            resolve_context_expr(scope, inner, assigned_fields, visiting, out)?;
            PatternExprOp::Not
        }
        ast::PatternExpr::Negate(inner) => {
            resolve_context_expr(scope, inner, assigned_fields, visiting, out)?;
            PatternExprOp::Negate
        }
    };
    out.push(op);
    Ok(())
}

impl ResolveIdent for DisasmConstantValue {
    type Output = DisasmConstantValue;

    fn resolve_ident(scope: &Scope, ident: ast::Ident) -> Result<Self, String> {
        match scope.lookup(ident) {
            Some(Local::Field(id)) => Ok(Self::LocalField(id)),
            Some(Local::InstStart) => Ok(Self::InstStart),
            Some(Local::InstNext) => Ok(Self::InstNext),
            Some(other) => Err(format!("{:?}<{}> in disasm expr", other, scope.debug(&ident))),
            None => {
                // Some SLEIGH specifications use context fields in disassembly expressions without
                // first declaring them in the constraint expression.
                let sym = scope
                    .globals
                    .lookup_kind(ident, SymbolKind::ContextField)
                    .map_err(|err| format!("Unexpected symbol kind in disasm expr: {err}"))?;
                Ok(Self::ContextField(scope.globals.context_fields[sym as usize].field))
            }
        }
    }
}

impl ResolveIdent for ContextModValue {
    type Output = ContextModValue;

    fn resolve_ident(scope: &Scope, ident: ast::Ident) -> Result<Self, String> {
        match scope.lookup(ident) {
            Some(Local::Field(id)) => {
                // Context modification expression are evaluated before local fields so the runtime
                // needs to know the original source of the field to evaluate them correctly.
                let field = scope.fields[id as usize];
                match scope.tokens.get(&id) {
                    Some(token) => Ok(Self::TokenField(*token, field)),
                    None => Ok(Self::ContextField(field)),
                }
            }
            Some(Local::Subtable(idx)) => Ok(Self::Subtable(idx)),
            Some(Local::InstStart) => Ok(Self::InstStart),
            Some(Local::InstNext) => Ok(Self::InstNext),
            Some(other) => {
                Err(format!("{:?}<{}> in context modification", other, scope.debug(&ident)))
            }
            None => {
                // Some SLEIGH specifications use context fields in context modifications
                // expressions without first declaring them in the constraint expression.
                let sym =
                    scope.globals.lookup_kind(ident, SymbolKind::ContextField).map_err(|err| {
                        format!("Unexpected symbol kind in disasm context write expr: {err}")
                    })?;
                Ok(Self::ContextField(scope.globals.context_fields[sym as usize].field))
            }
        }
    }
}

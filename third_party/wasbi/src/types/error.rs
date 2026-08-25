//! WASM error types.

/// The layer at which an error originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorLayer {
    /// Error during binary decoding (malformed module).
    Decode,
    /// Error during validation (invalid module).
    Validation,
    /// Error during instantiation (import resolution, linking).
    Instantiation,
    /// Runtime trap during execution.
    Trap,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WasmError {
    // ── Decode errors ───────────────────────────────────────────────────
    InvalidMagic,
    UnsupportedVersion,
    InvalidSection,
    InvalidOpcode(u8),
    InvalidLEB128,
    UnexpectedEnd,
    MalformedUtf8,
    ZeroByteExpected,
    CodeTooLarge,
    TooManyFunctions,
    TooManyImports,

    // ── Validation errors ───────────────────────────────────────────────
    LimitExceeded(&'static str),
    TypeMismatch,
    InvalidBlockType,
    DuplicateExport,
    ConstExprRequired,
    UndeclaredFuncRef,
    UnsupportedProposal,
    MultipleTables,
    BranchDepthExceeded,
    ImmutableGlobal,

    // ── Instantiation errors ────────────────────────────────────────────
    ImportNotFound(u32),
    FunctionNotFound(u32),

    // ── Runtime traps ───────────────────────────────────────────────────
    StackOverflow,
    StackUnderflow,
    OutOfBounds,
    DivisionByZero,
    UnreachableExecuted,
    OutOfFuel,
    MemoryOutOfBounds,
    CallStackOverflow,
    IntegerOverflow,
    FloatsDisabled,
    UndefinedElement,
    UninitializedElement(u32),
    IndirectCallTypeMismatch,
    GlobalIndexOutOfBounds,
    TableIndexOutOfBounds,
    InvalidConversionToInteger,
    NullFunctionReference,
    NullReference,
    NullI31Reference,
    NullStructReference,
    NullArrayReference,
    ArrayOutOfBounds,
    UninitializedLocal,
    UnalignedAtomic,
    UncaughtException,
    CastFailure,
}

impl WasmError {
    /// Classify this error by the layer where it originated.
    pub fn layer(&self) -> ErrorLayer {
        match self {
            // Decode
            Self::InvalidMagic
            | Self::UnsupportedVersion
            | Self::InvalidSection
            | Self::InvalidOpcode(_)
            | Self::InvalidLEB128
            | Self::UnexpectedEnd
            | Self::MalformedUtf8
            | Self::ZeroByteExpected
            | Self::CodeTooLarge
            | Self::TooManyFunctions
            | Self::TooManyImports => ErrorLayer::Decode,

            // Validation
            Self::LimitExceeded(_)
            | Self::TypeMismatch
            | Self::InvalidBlockType
            | Self::DuplicateExport
            | Self::ConstExprRequired
            | Self::UndeclaredFuncRef
            | Self::UnsupportedProposal
            | Self::MultipleTables
            | Self::BranchDepthExceeded
            | Self::ImmutableGlobal => ErrorLayer::Validation,

            // Instantiation
            Self::ImportNotFound(_) | Self::FunctionNotFound(_) => ErrorLayer::Instantiation,

            // Runtime traps
            _ => ErrorLayer::Trap,
        }
    }

    /// Returns `true` if this is a decode-phase error.
    pub fn is_decode_error(&self) -> bool {
        self.layer() == ErrorLayer::Decode
    }

    /// Returns `true` if this is a validation error.
    pub fn is_validation_error(&self) -> bool {
        self.layer() == ErrorLayer::Validation
    }

    /// Returns `true` if this is a runtime trap.
    pub fn is_trap(&self) -> bool {
        self.layer() == ErrorLayer::Trap
    }
}

impl core::fmt::Display for WasmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidMagic => write!(f, "invalid wasm magic number"),
            Self::UnsupportedVersion => write!(f, "unsupported wasm version"),
            Self::InvalidSection => write!(f, "invalid section"),
            Self::InvalidOpcode(op) => write!(f, "invalid opcode: 0x{op:02X}"),
            Self::InvalidLEB128 => write!(f, "invalid LEB128 encoding"),
            Self::UnexpectedEnd => write!(f, "unexpected end of section or function"),
            Self::MalformedUtf8 => write!(f, "malformed UTF-8 encoding"),
            Self::ZeroByteExpected => write!(f, "zero byte expected"),
            Self::CodeTooLarge => write!(f, "code section too large"),
            Self::TooManyFunctions => write!(f, "too many functions"),
            Self::TooManyImports => write!(f, "too many imports"),
            Self::LimitExceeded(limit) => write!(f, "resource limit exceeded: {limit}"),
            Self::TypeMismatch => write!(f, "type mismatch"),
            Self::InvalidBlockType => write!(f, "invalid block type"),
            Self::DuplicateExport => write!(f, "duplicate export name"),
            Self::ConstExprRequired => write!(f, "constant expression required"),
            Self::UndeclaredFuncRef => write!(f, "undeclared function reference"),
            Self::UnsupportedProposal => write!(f, "unsupported proposal"),
            Self::MultipleTables => write!(f, "multiple tables"),
            Self::BranchDepthExceeded => write!(f, "branch depth exceeded"),
            Self::ImmutableGlobal => write!(f, "global is immutable"),
            Self::ImportNotFound(idx) => write!(f, "import not found: index {idx}"),
            Self::FunctionNotFound(idx) => write!(f, "function not found: index {idx}"),
            Self::StackOverflow => write!(f, "stack overflow"),
            Self::StackUnderflow => write!(f, "stack underflow"),
            Self::OutOfBounds => write!(f, "out of bounds"),
            Self::DivisionByZero => write!(f, "integer divide by zero"),
            Self::UnreachableExecuted => write!(f, "unreachable"),
            Self::OutOfFuel => write!(f, "out of fuel"),
            Self::MemoryOutOfBounds => write!(f, "out of bounds memory access"),
            Self::CallStackOverflow => write!(f, "call stack exhausted"),
            Self::IntegerOverflow => write!(f, "integer overflow"),
            Self::FloatsDisabled => write!(f, "floating-point operations disabled"),
            Self::UndefinedElement => write!(f, "undefined element"),
            Self::UninitializedElement(idx) => write!(f, "uninitialized element: {idx}"),
            Self::IndirectCallTypeMismatch => write!(f, "indirect call type mismatch"),
            Self::GlobalIndexOutOfBounds => write!(f, "global index out of bounds"),
            Self::TableIndexOutOfBounds => write!(f, "table index out of bounds"),
            Self::InvalidConversionToInteger => write!(f, "invalid conversion to integer"),
            Self::NullFunctionReference => write!(f, "null function reference"),
            Self::NullReference => write!(f, "null reference"),
            Self::NullI31Reference => write!(f, "null i31 reference"),
            Self::NullStructReference => write!(f, "null struct reference"),
            Self::NullArrayReference => write!(f, "null array reference"),
            Self::ArrayOutOfBounds => write!(f, "array index out of bounds"),
            Self::UninitializedLocal => write!(f, "uninitialized local"),
            Self::UnalignedAtomic => write!(f, "unaligned atomic"),
            Self::UncaughtException => write!(f, "uncaught exception"),
            Self::CastFailure => write!(f, "cast failure"),
        }
    }
}

impl core::fmt::Display for ErrorLayer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode => write!(f, "decode"),
            Self::Validation => write!(f, "validation"),
            Self::Instantiation => write!(f, "instantiation"),
            Self::Trap => write!(f, "trap"),
        }
    }
}

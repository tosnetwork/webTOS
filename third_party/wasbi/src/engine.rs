//! Engine configuration and shared state.

use crate::config::Config;

/// Shared execution engine holding configuration.
///
/// An `Engine` is cheap to create and can be shared across multiple
/// [`Module`](crate::module::Module) and [`Instance`](crate::instance::Instance)
/// values.
#[derive(Debug, Clone)]
pub struct Engine {
    config: Config,
}

impl Engine {
    /// Create an engine with the given configuration.
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Access the engine configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

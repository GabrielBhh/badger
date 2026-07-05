//! Point-in-time system samplers backing `badger status`: everything here
//! reads through `Ctx::root` (never an absolute `/proc` or `/sys` path
//! directly) so tests can fabricate the trees they read, the same sandbox
//! convention `analyze::disk` established.

pub mod cpu;
pub mod mem;
pub mod psi;

//! Point-in-time system samplers backing `badger status`: everything here
//! reads through `Ctx::root` (never an absolute `/proc` or `/sys` path
//! directly) so tests can fabricate the trees they read, the same sandbox
//! convention `analyze::disk` established.

pub mod cachyos;
pub mod cpu;
pub mod disk;
pub mod health;
pub mod hwmon;
pub mod mem;
pub mod net;
pub mod power;
pub mod procs;
pub mod psi;

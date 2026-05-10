/// rcop-core — shared library protokol RCOP
///
/// Library ini di-compile ke dua bentuk:
/// - cdylib  : .so / .dll / .dylib — untuk Go (CGo) dan Python (ctypes)
/// - staticlib: .a — untuk Android NDK (JNI via CMake)
///
/// Modul publik:
/// - types    : RcopPacket, PacketType, RcopError, konstanta
/// - checksum : compute dan verify CRC32
/// - packet   : build() dan parse()
/// - ffi      : fungsi C-exported tanpa name mangling

pub mod checksum;
pub mod ffi;
pub mod packet;
pub mod types;

// Re-export tipe yang paling sering dipakai supaya user cukup `use rcop_core::*`
pub use types::{PacketType, RcopError, RcopPacket, HEADER_SIZE, RCOP_MAGIC};
pub use packet::{build, parse};
pub use checksum::{compute as checksum_compute, verify as checksum_verify};
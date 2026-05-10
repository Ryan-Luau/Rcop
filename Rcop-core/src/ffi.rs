/// FFI (Foreign Function Interface) exports.
///
/// Fungsi-fungsi di sini bisa dipanggil dari:
/// - Go (via CGo):     import "C" -> C.rcop_build_packet(...)
/// - Kotlin/Android:   System.loadLibrary("rcop_core") -> native method
/// - Python (ctypes):  lib.rcop_verify_checksum(...)
///
/// Semua parameter pakai tipe C-compatible (pointer, integer primitif).
/// Tidak ada tipe Rust-specific yang bocor ke luar.

use std::slice;
use crate::{checksum, packet};
use crate::types::HEADER_SIZE;

// ─────────────────────────────────────────────────────────────────────────────
// BUILD
// ─────────────────────────────────────────────────────────────────────────────

/// Bangun paket RCOP ke buffer yang disediakan caller.
///
/// # Parameters (C)
/// - `ptype`        : u8  — tipe paket
/// - `seq_id`       : u32 — nomor urut
/// - `payload`      : *const u8 — pointer ke payload (NULL jika kosong)
/// - `payload_len`  : usize — panjang payload
/// - `out`          : *mut u8 — buffer output yang harus disediakan caller
/// - `out_len`      : *mut usize — [in] kapasitas buffer, [out] byte yang ditulis
///
/// # Return
/// -  0 = sukses
/// - -1 = buffer output terlalu kecil
/// - -2 = pointer null tidak valid
#[no_mangle]
pub unsafe extern "C" fn rcop_build_packet(
    ptype: u8,
    seq_id: u32,
    payload: *const u8,
    payload_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> i32 {
    if out.is_null() || out_len.is_null() {
        return -2;
    }

    let payload_slice = if payload.is_null() || payload_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(payload, payload_len)
    };

    let built = packet::build(ptype, seq_id, payload_slice);

    let capacity = *out_len;
    if capacity < built.len() {
        // Beritahu caller berapa byte yang dibutuhkan
        *out_len = built.len();
        return -1;
    }

    let out_slice = slice::from_raw_parts_mut(out, built.len());
    out_slice.copy_from_slice(&built);
    *out_len = built.len();
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// PARSE
// ─────────────────────────────────────────────────────────────────────────────

/// Hasil parse paket — C-compatible struct.
/// Payload tidak ada di sini; caller ambil via rcop_get_payload().
#[repr(C)]
pub struct CRcopPacket {
    pub ptype: u8,
    pub seq_id: u32,
    pub payload_len: u32,
    pub checksum: u32,
    pub timestamp: u64,
    /// Error code: 0 = ok, non-zero = gagal (lihat RCOP_ERR_*)
    pub error_code: i32,
}

/// Error codes untuk CRcopPacket.error_code
pub const RCOP_OK:                    i32 = 0;
pub const RCOP_ERR_BUFFER_TOO_SMALL:  i32 = 1;
pub const RCOP_ERR_INVALID_MAGIC:     i32 = 2;
pub const RCOP_ERR_UNKNOWN_TYPE:      i32 = 3;
pub const RCOP_ERR_CHECKSUM_MISMATCH: i32 = 4;
pub const RCOP_ERR_PAYLOAD_MISMATCH:  i32 = 5;

/// Parse buffer menjadi CRcopPacket.
///
/// Caller cek `result.error_code == 0` sebelum menggunakan field lain.
/// Untuk ambil payload, panggil `rcop_get_payload()` dengan buffer yang sama.
#[no_mangle]
pub unsafe extern "C" fn rcop_parse_packet(
    data: *const u8,
    data_len: usize,
    out: *mut CRcopPacket,
) -> i32 {
    if data.is_null() || out.is_null() {
        return -2;
    }

    let buf = slice::from_raw_parts(data, data_len);

    match packet::parse(buf) {
        Ok(pkt) => {
            (*out).ptype       = pkt.ptype;
            (*out).seq_id      = pkt.seq_id;
            (*out).payload_len = pkt.payload_len;
            (*out).checksum    = pkt.checksum;
            (*out).timestamp   = pkt.timestamp;
            (*out).error_code  = RCOP_OK;
            RCOP_OK
        }
        Err(e) => {
            use crate::types::RcopError::*;
            let code = match e {
                BufferTooSmall        => RCOP_ERR_BUFFER_TOO_SMALL,
                InvalidMagic          => RCOP_ERR_INVALID_MAGIC,
                UnknownPacketType     => RCOP_ERR_UNKNOWN_TYPE,
                ChecksumMismatch      => RCOP_ERR_CHECKSUM_MISMATCH,
                PayloadLengthMismatch => RCOP_ERR_PAYLOAD_MISMATCH,
            };
            if !out.is_null() {
                (*out).error_code = code;
            }
            code
        }
    }
}

/// Salin payload dari buffer paket ke buffer output caller.
///
/// Harus dipanggil setelah rcop_parse_packet() sukses.
/// `payload_out` harus punya kapasitas minimal `payload_len` byte.
///
/// # Return
/// - 0  = sukses
/// - -1 = buffer output terlalu kecil
/// - -2 = pointer null
#[no_mangle]
pub unsafe extern "C" fn rcop_get_payload(
    data: *const u8,
    data_len: usize,
    payload_out: *mut u8,
    payload_out_len: usize,
    payload_actual_len: u32,
) -> i32 {
    if data.is_null() || payload_out.is_null() {
        return -2;
    }
    let needed = payload_actual_len as usize;
    if payload_out_len < needed {
        return -1;
    }
    if data_len < HEADER_SIZE + needed {
        return -1;
    }
    let src = slice::from_raw_parts(data.add(HEADER_SIZE), needed);
    let dst = slice::from_raw_parts_mut(payload_out, needed);
    dst.copy_from_slice(src);
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// UTILITIES
// ─────────────────────────────────────────────────────────────────────────────

/// Verifikasi checksum buffer paket. Bisa dipanggil sebelum parse penuh.
///
/// # Return
/// - 1 = checksum valid
/// - 0 = tidak valid atau buffer terlalu pendek
#[no_mangle]
pub unsafe extern "C" fn rcop_verify_checksum(data: *const u8, data_len: usize) -> i32 {
    if data.is_null() || data_len < HEADER_SIZE {
        return 0;
    }
    let buf = slice::from_raw_parts(data, data_len);
    let stored = u32::from_be_bytes(buf[13..17].try_into().unwrap_or([0; 4]));
    let mut tmp = buf.to_vec();
    tmp[13..17].copy_from_slice(&[0u8; 4]);
    if checksum::verify(&tmp, stored) { 1 } else { 0 }
}

/// Kembalikan ukuran minimum buffer untuk membangun paket
/// dengan payload sepanjang `payload_len` byte.
#[no_mangle]
pub extern "C" fn rcop_packet_size(payload_len: usize) -> usize {
    HEADER_SIZE + payload_len
}

/// Kembalikan versi protokol sebagai u32.
/// Format: (major << 16) | (minor << 8) | patch
/// Misal: 0x00_01_00 = v0.1.0
#[no_mangle]
pub extern "C" fn rcop_version() -> u32 {
    (0u32 << 16) | (1u32 << 8) | 0u32
}
use std::time::{SystemTime, UNIX_EPOCH};

use crate::checksum;
use crate::types::{RcopError, RcopPacket, HEADER_SIZE, RCOP_MAGIC};

// ── Format wire (urutan byte dalam buffer) ───────────────────────────────────
//
//  Offset  Ukuran  Field
//  ──────  ──────  ─────────────────────────────────────────────────────
//   0      4       magic         = 0x52 0x43 0x4F 0x50 ("RCOP")
//   4      1       ptype         tipe paket (PacketType as u8)
//   5      4       seq_id        big-endian u32
//   9      4       payload_len   big-endian u32
//  13      4       checksum      CRC32 dari [magic..payload_end], big-endian u32
//  17      8       timestamp     Unix microseconds, big-endian u64
//  25      N       payload       N = payload_len byte
//
// Total minimum (tanpa payload): 25 byte
// ─────────────────────────────────────────────────────────────────────────────

/// Ambil timestamp saat ini dalam microsecond sejak Unix epoch.
fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

/// Bangun paket RCOP menjadi Vec<u8> siap kirim lewat socket.
///
/// # Arguments
/// * `ptype`   – tipe paket (PacketType as u8)
/// * `seq_id`  – nomor urut paket dari pengirim
/// * `payload` – data payload (boleh kosong)
///
/// # Proses
/// 1. Susun header sementara dengan checksum = 0
/// 2. Hitung CRC32 dari header + payload
/// 3. Tulis checksum ke posisi yang benar
pub fn build(ptype: u8, seq_id: u32, payload: &[u8]) -> Vec<u8> {
    let payload_len = payload.len() as u32;
    let timestamp   = now_micros();
    let total_size  = HEADER_SIZE + payload.len();

    let mut buf = Vec::with_capacity(total_size);

    // Magic
    buf.extend_from_slice(&RCOP_MAGIC);
    // Type
    buf.push(ptype);
    // Seq ID
    buf.extend_from_slice(&seq_id.to_be_bytes());
    // Payload length
    buf.extend_from_slice(&payload_len.to_be_bytes());
    // Checksum placeholder (akan diisi setelah hitung)
    buf.extend_from_slice(&[0u8; 4]);
    // Timestamp
    buf.extend_from_slice(&timestamp.to_be_bytes());
    // Payload
    buf.extend_from_slice(payload);

    // Hitung CRC32 dari seluruh buffer (checksum field sementara = 0)
    let csum = checksum::compute(&buf);

    // Tulis checksum ke offset 13
    buf[13..17].copy_from_slice(&csum.to_be_bytes());

    buf
}

/// Parse buffer bytes menjadi RcopPacket.
///
/// # Errors
/// Kembalikan RcopError jika:
/// - Buffer terlalu pendek (< HEADER_SIZE)
/// - Magic bytes tidak cocok
/// - Tipe paket tidak dikenal
/// - Payload length tidak sesuai sisa buffer
/// - Checksum tidak valid
pub fn parse(buf: &[u8]) -> Result<RcopPacket, RcopError> {
    // 1. Cek panjang minimum
    if buf.len() < HEADER_SIZE {
        return Err(RcopError::BufferTooSmall);
    }

    // 2. Validasi magic
    if buf[0..4] != RCOP_MAGIC {
        return Err(RcopError::InvalidMagic);
    }

    // 3. Baca field header
    let ptype       = buf[4];
    let seq_id      = u32::from_be_bytes(buf[5..9].try_into().unwrap());
    let payload_len = u32::from_be_bytes(buf[9..13].try_into().unwrap()) as usize;
    let checksum    = u32::from_be_bytes(buf[13..17].try_into().unwrap());
    let timestamp   = u64::from_be_bytes(buf[17..25].try_into().unwrap());

    // 4. Validasi tipe paket
    if crate::types::PacketType::from_u8(ptype).is_none() {
        return Err(RcopError::UnknownPacketType);
    }

    // 5. Validasi panjang payload
    let expected_total = HEADER_SIZE + payload_len;
    if buf.len() < expected_total {
        return Err(RcopError::PayloadLengthMismatch);
    }

    // 6. Verifikasi checksum
    // Cara: salin buffer, set checksum field jadi 0, hitung ulang, bandingkan
    let mut check_buf = buf[..expected_total].to_vec();
    check_buf[13..17].copy_from_slice(&[0u8; 4]);
    if !checksum::verify(&check_buf, checksum) {
        return Err(RcopError::ChecksumMismatch);
    }

    // 7. Ambil payload
    let payload = buf[HEADER_SIZE..expected_total].to_vec();

    Ok(RcopPacket {
        ptype,
        seq_id,
        payload_len: payload_len as u32,
        checksum,
        timestamp,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PacketType, RcopError};

    fn ping_packet(seq: u32) -> Vec<u8> {
        build(PacketType::Ping as u8, seq, b"")
    }

    #[test]
    fn build_menghasilkan_magic_benar() {
        let buf = ping_packet(0);
        assert_eq!(&buf[0..4], &RCOP_MAGIC);
    }

    #[test]
    fn build_parse_roundtrip() {
        let payload = b"test payload data";
        let buf = build(PacketType::Frame as u8, 42, payload);
        let pkt = parse(&buf).expect("parse harus berhasil");

        assert_eq!(pkt.ptype, PacketType::Frame as u8);
        assert_eq!(pkt.seq_id, 42);
        assert_eq!(pkt.payload, payload);
    }

    #[test]
    fn parse_payload_kosong() {
        let buf = ping_packet(1);
        let pkt = parse(&buf).unwrap();
        assert_eq!(pkt.payload_len, 0);
        assert!(pkt.payload.is_empty());
    }

    #[test]
    fn parse_buffer_terlalu_pendek() {
        let buf = vec![0u8; 10]; // kurang dari HEADER_SIZE (25)
        assert_eq!(parse(&buf), Err(RcopError::BufferTooSmall));
    }

    #[test]
    fn parse_magic_salah() {
        let mut buf = ping_packet(0);
        buf[0] = 0xFF; // rusak magic
        assert_eq!(parse(&buf), Err(RcopError::InvalidMagic));
    }

    #[test]
    fn parse_checksum_korup() {
        let mut buf = ping_packet(0);
        buf[13] ^= 0xFF; // rusak checksum
        assert_eq!(parse(&buf), Err(RcopError::ChecksumMismatch));
    }

    #[test]
    fn parse_payload_korup() {
        let mut buf = build(PacketType::Audio as u8, 5, b"audio data");
        *buf.last_mut().unwrap() ^= 0xFF; // rusak 1 byte payload
        assert_eq!(parse(&buf), Err(RcopError::ChecksumMismatch));
    }

    #[test]
    fn parse_tipe_tidak_dikenal() {
        let mut buf = ping_packet(0);
        buf[4] = 0xFF; // tipe yang tidak ada
        // Checksum akan salah juga, tapi tipe dicek lebih dulu? Tidak —
        // checksum dicek setelah tipe. Tapi kita set checksum ulang supaya tes tipe murni.
        let csum = {
            let mut tmp = buf.clone();
            tmp[13..17].copy_from_slice(&[0u8; 4]);
            checksum::compute(&tmp)
        };
        buf[13..17].copy_from_slice(&csum.to_be_bytes());
        assert_eq!(parse(&buf), Err(RcopError::UnknownPacketType));
    }

    #[test]
    fn seq_id_tersimpan_benar() {
        for seq in [0u32, 1, 255, 65535, u32::MAX] {
            let buf = build(PacketType::Ack as u8, seq, b"");
            let pkt = parse(&buf).unwrap();
            assert_eq!(pkt.seq_id, seq);
        }
    }
}
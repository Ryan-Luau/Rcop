/// Integration test rcop-core.
///
/// Test ini jalan dengan `cargo test` dan mencakup:
/// - Roundtrip build → parse untuk semua tipe paket
/// - Simulasi skenario nyata (handshake, ping-pong, frame stream)
/// - Validasi error handling
/// - Test FFI functions

use rcop_core::{
    build, parse,
    PacketType, RcopError,
    ffi::{
        rcop_build_packet, rcop_parse_packet, rcop_verify_checksum,
        rcop_packet_size, rcop_version, CRcopPacket, RCOP_OK,
    },
};

// ─── Roundtrip semua tipe paket ───────────────────────────────────────────────

#[test]
fn roundtrip_semua_tipe_paket() {
    let cases: &[(PacketType, &[u8])] = &[
        (PacketType::Ping,       b""),
        (PacketType::Pong,       b""),
        (PacketType::Ack,        b""),
        (PacketType::Handshake,  br#"{"res":"1920x1080","codec":"h264","fps":60}"#),
        (PacketType::Config,     br#"{"fps":60,"bitrate":8000000,"codec":"h264"}"#),
        (PacketType::TaskReq,    br#"{"task":"launch","app":"game.exe"}"#),
        (PacketType::Frame,      &[0xAB; 1024]),   // simulasi frame kecil
        (PacketType::Audio,      &[0x00; 4096]),   // simulasi audio buffer
        (PacketType::Input,      br#"{"type":"touch","x":540,"y":960,"p":0.8}"#),
        (PacketType::Disconnect, br#"{"reason":"user_request"}"#),
    ];

    for (ptype, payload) in cases {
        let buf = build(*ptype as u8, 1, payload);
        let pkt = parse(&buf).unwrap_or_else(|e| {
            panic!("parse gagal untuk {:?}: {}", ptype, e)
        });
        assert_eq!(pkt.ptype, *ptype as u8);
        assert_eq!(&pkt.payload, payload);
    }
}

// ─── Simulasi skenario: handshake → config → ping/pong ───────────────────────

#[test]
fn skenario_koneksi_awal() {
    // 1. HP kirim HANDSHAKE
    let handshake_payload = br#"{"res":"1080x2400","codec":["h264","h265"],"fps_max":120}"#;
    let hs = build(PacketType::Handshake as u8, 0, handshake_payload);
    let hs_pkt = parse(&hs).unwrap();
    assert_eq!(hs_pkt.seq_id, 0);

    // 2. Laptop balas CONFIG
    let config_payload = br#"{"fps":60,"bitrate":6000000,"codec":"h264","audio":"pcm_s16le"}"#;
    let cfg = build(PacketType::Config as u8, 0, config_payload);
    let cfg_pkt = parse(&cfg).unwrap();
    assert_eq!(cfg_pkt.ptype, PacketType::Config as u8);

    // 3. HP kirim PING
    let ping = build(PacketType::Ping as u8, 1, b"");
    let ping_pkt = parse(&ping).unwrap();
    assert_eq!(ping_pkt.ptype, PacketType::Ping as u8);
    assert!(ping_pkt.payload.is_empty());

    // 4. Laptop balas PONG
    let pong = build(PacketType::Pong as u8, 1, b"");
    let pong_pkt = parse(&pong).unwrap();
    assert_eq!(pong_pkt.ptype, PacketType::Pong as u8);
}

// ─── Simulasi stream frame dengan seq_id berurutan ───────────────────────────

#[test]
fn skenario_frame_stream() {
    let frame_data = vec![0xFFu8; 512]; // dummy frame
    for seq in 0u32..10 {
        let buf = build(PacketType::Frame as u8, seq, &frame_data);
        let pkt = parse(&buf).unwrap();
        assert_eq!(pkt.seq_id, seq);
        assert_eq!(pkt.payload.len(), 512);
    }
}

// ─── Error handling ───────────────────────────────────────────────────────────

#[test]
fn error_buffer_kosong() {
    assert_eq!(parse(&[]), Err(RcopError::BufferTooSmall));
}

#[test]
fn error_magic_salah() {
    let mut buf = build(PacketType::Ping as u8, 0, b"");
    buf[1] = 0x00;
    assert_eq!(parse(&buf), Err(RcopError::InvalidMagic));
}

#[test]
fn error_payload_dicrop() {
    let buf = build(PacketType::Frame as u8, 0, b"data panjang");
    // Potong buffer sebelum payload selesai
    let short = &buf[..buf.len() - 3];
    assert_eq!(parse(short), Err(RcopError::PayloadLengthMismatch));
}

// ─── FFI functions ────────────────────────────────────────────────────────────

#[test]
fn ffi_build_dan_parse() {
    let payload = b"ffi test payload";
    let buf_size = rcop_packet_size(payload.len());
    let mut out_buf = vec![0u8; buf_size];
    let mut out_len = buf_size;

    let rc = unsafe {
        rcop_build_packet(
            PacketType::TaskReq as u8,
            99,
            payload.as_ptr(),
            payload.len(),
            out_buf.as_mut_ptr(),
            &mut out_len,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(out_len, buf_size);

    let mut cpkt = CRcopPacket {
        ptype: 0, seq_id: 0, payload_len: 0,
        checksum: 0, timestamp: 0, error_code: -1,
    };
    let rc2 = unsafe {
        rcop_parse_packet(out_buf.as_ptr(), out_len, &mut cpkt)
    };
    assert_eq!(rc2, RCOP_OK);
    assert_eq!(cpkt.ptype, PacketType::TaskReq as u8);
    assert_eq!(cpkt.seq_id, 99);
    assert_eq!(cpkt.payload_len, payload.len() as u32);
}

#[test]
fn ffi_verify_checksum_valid() {
    let buf = build(PacketType::Ping as u8, 0, b"");
    let result = unsafe { rcop_verify_checksum(buf.as_ptr(), buf.len()) };
    assert_eq!(result, 1);
}

#[test]
fn ffi_verify_checksum_korup() {
    let mut buf = build(PacketType::Ping as u8, 0, b"");
    buf[5] ^= 0xFF; // rusak seq_id
    let result = unsafe { rcop_verify_checksum(buf.as_ptr(), buf.len()) };
    assert_eq!(result, 0);
}

#[test]
fn ffi_version_format() {
    let v = rcop_version();
    // Format: (major << 16) | (minor << 8) | patch
    let major = (v >> 16) & 0xFF;
    let minor = (v >> 8)  & 0xFF;
    let patch =  v        & 0xFF;
    // Versi 0.1.0
    assert_eq!(major, 0);
    assert_eq!(minor, 1);
    assert_eq!(patch, 0);
}

#[test]
fn ffi_buffer_terlalu_kecil() {
    let payload = b"data";
    let mut out_buf = vec![0u8; 5]; // jauh terlalu kecil
    let mut out_len = 5usize;
    let rc = unsafe {
        rcop_build_packet(
            PacketType::Ping as u8, 0,
            payload.as_ptr(), payload.len(),
            out_buf.as_mut_ptr(), &mut out_len,
        )
    };
    assert_eq!(rc, -1);
    // out_len sekarang berisi ukuran yang dibutuhkan
    assert!(out_len > 5);
}
/// Magic bytes yang ada di awal setiap paket RCOP.
/// Spell-out: 'R','C','O','P' = 0x52434F50
pub const RCOP_MAGIC: [u8; 4] = [0x52, 0x43, 0x4F, 0x50];

/// Ukuran header tetap (tanpa payload):
/// 4 (magic) + 1 (type) + 4 (seq) + 4 (payload_len) + 4 (checksum) + 8 (timestamp) = 25 byte
pub const HEADER_SIZE: usize = 25;

/// Tipe-tipe paket dalam protokol RCOP.
/// repr(u8) supaya bisa langsung cast ke byte saat serialisasi.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// HP minta laptop jalankan suatu task (game, proses, dll)
    TaskReq    = 0x01,
    /// Laptop kirim satu frame video ke HP
    Frame      = 0x02,
    /// HP kirim event input (sentuhan, keyboard, gamepad)
    Input      = 0x03,
    /// Konfirmasi penerimaan paket (acknowledge)
    Ack        = 0x04,
    /// Stream audio PCM dari laptop ke HP
    Audio      = 0x05,
    /// HP cek latency ke laptop
    Ping       = 0x06,
    /// Laptop balas ping
    Pong       = 0x07,
    /// HP perkenalkan kapabilitasnya (resolusi, codec, dll)
    Handshake  = 0x08,
    /// Laptop kirim konfigurasi sesi (FPS, bitrate, codec)
    Config     = 0x09,
    /// Salah satu pihak minta putus koneksi
    Disconnect = 0x0A,
}

impl PacketType {
    /// Parse byte jadi PacketType. Kembalikan None kalau tidak dikenal.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::TaskReq),
            0x02 => Some(Self::Frame),
            0x03 => Some(Self::Input),
            0x04 => Some(Self::Ack),
            0x05 => Some(Self::Audio),
            0x06 => Some(Self::Ping),
            0x07 => Some(Self::Pong),
            0x08 => Some(Self::Handshake),
            0x09 => Some(Self::Config),
            0x0A => Some(Self::Disconnect),
            _    => None,
        }
    }
}

/// Representasi satu paket RCOP yang sudah di-parse.
/// Struct ini yang berpindah tangan antar komponen (Go, Kotlin, Python via FFI).
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RcopPacket {
    /// Tipe paket (sebagai u8 supaya C-compatible)
    pub ptype: u8,
    /// Nomor urut — deteksi loss dan ordering
    pub seq_id: u32,
    /// Panjang payload dalam byte
    pub payload_len: u32,
    /// CRC32 checksum dari seluruh paket (header + payload)
    pub checksum: u32,
    /// Waktu paket dibuat, Unix epoch dalam microsecond
    pub timestamp: u64,
    /// Payload aktual — bisa kosong (ping/pong/ack)
    pub payload: Vec<u8>,
}

/// Error yang mungkin terjadi saat build atau parse paket.
#[derive(Debug, PartialEq, Eq)]
pub enum RcopError {
    /// Magic bytes tidak cocok — bukan paket RCOP
    InvalidMagic,
    /// Data terlalu pendek, header tidak lengkap
    BufferTooSmall,
    /// Tipe paket tidak dikenal
    UnknownPacketType,
    /// CRC32 tidak cocok — data korup atau diubah
    ChecksumMismatch,
    /// Payload length di header tidak cocok dengan data aktual
    PayloadLengthMismatch,
}

impl std::fmt::Display for RcopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMagic          => write!(f, "magic bytes tidak valid"),
            Self::BufferTooSmall        => write!(f, "buffer terlalu kecil"),
            Self::UnknownPacketType     => write!(f, "tipe paket tidak dikenal"),
            Self::ChecksumMismatch      => write!(f, "checksum tidak cocok (data korup)"),
            Self::PayloadLengthMismatch => write!(f, "panjang payload tidak sesuai"),
        }
    }
}
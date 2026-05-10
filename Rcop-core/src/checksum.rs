use crc32fast::Hasher;

/// Hitung CRC32 dari slice byte apapun.
/// Dipakai saat build paket (masukkan ke field checksum)
/// dan saat verifikasi (bandingkan dengan checksum yang diterima).
pub fn compute(data: &[u8]) -> u32 {
    let mut h = Hasher::new();
    h.update(data);
    h.finalize()
}

/// Verifikasi apakah checksum yang diberikan cocok dengan data.
/// Kembalikan true kalau valid, false kalau korup.
pub fn verify(data: &[u8], expected: u32) -> bool {
    compute(data) == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_konsisten() {
        let data = b"hello rcop";
        let c1 = compute(data);
        let c2 = compute(data);
        assert_eq!(c1, c2, "checksum harus selalu sama untuk input yang sama");
    }

    #[test]
    fn checksum_verify_valid() {
        let data = b"frame data contoh";
        let csum = compute(data);
        assert!(verify(data, csum));
    }

    #[test]
    fn checksum_verify_korup() {
        let data = b"frame data contoh";
        let csum = compute(data);
        // Ubah satu byte — checksum harus gagal
        let mut rusak = data.to_vec();
        rusak[0] ^= 0xFF;
        assert!(!verify(&rusak, csum), "data korup harus gagal verifikasi");
    }

    #[test]
    fn checksum_data_kosong() {
        // Data kosong pun harus punya checksum yang valid
        let csum = compute(b"");
        assert!(verify(b"", csum));
    }
}
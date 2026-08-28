//! md5 compiled to wasm32 — the ceiling a hot-block JIT-to-wasm approaches for
//! this workload. Same arithmetic the guest's md5sum runs, compiled by rustc
//! to wasm and run in the same browser wasm engine, instead of interpreted
//! p-code op by op. Not a JIT; the upper bound one would chase.

const S: [u32; 64] = [
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
];
const K: [u32; 64] = [
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391,
];

/// Hashes `len` bytes at offset 0 of linear memory, over `rounds` full blocks
/// of that data, returning the low 32 bits of the digest so the call cannot be
/// optimized away. The rounds argument lets the caller run a lot of md5 work
/// from one call, isolating steady-state throughput from call overhead.
#[no_mangle]
pub extern "C" fn md5_bench(ptr: *const u8, len: usize, rounds: u32) -> u32 {
    let data = unsafe { core::slice::from_raw_parts(ptr, len) };
    let mut acc = 0u32;
    for _ in 0..rounds {
        let (mut a0, mut b0, mut c0, mut d0) = (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);
        for chunk in data.chunks(64) {
            let mut m = [0u32; 16];
            for (i, mm) in m.iter_mut().enumerate() {
                let base = i * 4;
                if base + 3 < chunk.len() {
                    *mm = u32::from_le_bytes([chunk[base], chunk[base+1], chunk[base+2], chunk[base+3]]);
                }
            }
            let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
            for i in 0..64 {
                let (f, g) = match i {
                    0..=15  => ((b & c) | (!b & d), i),
                    16..=31 => ((d & b) | (!d & c), (5*i + 1) % 16),
                    32..=47 => (b ^ c ^ d, (3*i + 5) % 16),
                    _       => (c ^ (b | !d), (7*i) % 16),
                };
                let f = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]);
                a = d; d = c; c = b;
                b = b.wrapping_add(f.rotate_left(S[i]));
            }
            a0 = a0.wrapping_add(a); b0 = b0.wrapping_add(b);
            c0 = c0.wrapping_add(c); d0 = d0.wrapping_add(d);
        }
        acc ^= a0;
    }
    acc
}

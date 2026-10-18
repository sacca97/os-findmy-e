//! The client half of Apple's SRP-6a, exactly as `findmy.reports.account` drives pysrp (`_pysrp` with
//! `rfc5054_enable()` and `no_username_in_x()`, SHA-256, the RFC 5054 2048-bit group):
//!
//! ```text
//! k  = H(N ‖ PAD(g))                 x  = H(s ‖ H(":" ‖ P))     (no username in x)
//! u  = H(PAD(A) ‖ PAD(B))            S  = (B − k·g^x)^(a + u·x) mod N
//! K  = H(S)                          M1 = H((H(N) ⊕ H(PAD(g))) ‖ H(I) ‖ s ‖ A ‖ B ‖ K)
//! M2 = H(A ‖ M1 ‖ K)
//! ```
//!
//! Big integers are serialised minimally (no leading zero, no sign byte) except where `PAD()` says
//! 256 bytes.
//!
//! **Deliberate fidelity to the Python over the spec:** `01-authentication.md` §4.6 says Apple
//! hashes `u` over unpadded A and B, but pysrp in rfc5054 mode pads both; that is what has
//! authenticated every session so far. The two differ only when A or B has a leading zero byte.

use num_bigint::BigUint;
use sha2::{Digest, Sha256};

const N_HEX: &str = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73";

/// The RFC 5054 2048-bit group order, as a big-endian byte string.
pub fn group_n() -> BigUint {
    BigUint::parse_bytes(N_HEX.as_bytes(), 16).expect("group order")
}

const N_BYTES: usize = 256;

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// pysrp's `long_to_bytes`: big-endian with no leading zero bytes (zero is the empty string).
pub fn minimal(n: &BigUint) -> Vec<u8> {
    n.to_bytes_be()
}

fn pad(b: &[u8]) -> Vec<u8> {
    if b.len() >= N_BYTES {
        b.to_vec()
    } else {
        let mut out = vec![0u8; N_BYTES - b.len()];
        out.extend_from_slice(b);
        out
    }
}

fn h_n_xor_h_g() -> [u8; 32] {
    let hn = sha256(&[&minimal(&group_n())]);
    let hg = sha256(&[&pad(&minimal(&BigUint::from(2u8)))]);
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = hn[i] ^ hg[i];
    }
    out
}

fn k_mult() -> BigUint {
    let g = BigUint::from(2u8);
    BigUint::from_bytes_be(&sha256(&[&minimal(&group_n()), &pad(&minimal(&g))]))
}

/// 256 random bytes with the top bit set, as pysrp's `get_random_of_length(256)`.
pub fn random_ephemeral() -> [u8; N_BYTES] {
    use rand::RngCore;
    let mut a = [0u8; N_BYTES];
    rand::thread_rng().fill_bytes(&mut a);
    a[0] |= 0x80;
    a
}

/// The client half of one SRP exchange. Holds only the ephemeral and the computed proofs.
pub struct SrpClient {
    username: String,
    identity_in_x: bool,
    a: BigUint,
    big_a: BigUint,
    expected_m2: Vec<u8>,
    key: Option<[u8; 32]>,
    session_key: Option<[u8; 32]>,
}

impl SrpClient {
    /// `a` is the secret ephemeral, big-endian.
    pub fn new(username: impl Into<String>, a: &[u8]) -> SrpClient {
        let a_num = BigUint::from_bytes_be(a);
        let big_a = BigUint::from(2u8).modpow(&a_num, &group_n());
        SrpClient {
            username: username.into(),
            identity_in_x: false,
            a: a_num,
            big_a,
            expected_m2: Vec::new(),
            key: None,
            session_key: None,
        }
    }

    /// Standard SRP-6a: include the identity in the private-key hash (`x = H(s ‖ H(I ‖ ":" ‖ P))`).
    /// Grand Slam omits it; escrow recovery includes it.
    pub fn new_standard(username: impl Into<String>, a: &[u8]) -> SrpClient {
        let mut client = SrpClient::new(username, a);
        client.identity_in_x = true;
        client
    }

    /// Set the identity after construction (escrow recovery learns it from `srp_init`).
    pub fn set_username(&mut self, username: impl Into<String>) {
        self.username = username.into();
    }

    /// `A2k`: A, minimal big-endian.
    pub fn public_a(&self) -> Vec<u8> {
        minimal(&self.big_a)
    }

    /// The session key K once the server proof has verified, else `None` (pysrp's `get_session_key`).
    pub fn session_key(&self) -> Option<&[u8; 32]> {
        self.session_key.as_ref()
    }

    /// `M1` for the server's salt and `B`, given the derived password `P`; `None` when the SRP-6a
    /// safety checks fail.
    pub fn process_challenge(&mut self, salt: &[u8], server_b: &[u8], password: &[u8]) -> Option<Vec<u8>> {
        let n = group_n();
        let b = BigUint::from_bytes_be(server_b);
        if (&b % &n) == BigUint::ZERO {
            return None;
        }
        let u = BigUint::from_bytes_be(&sha256(&[&pad(&minimal(&self.big_a)), &pad(&minimal(&b))]));
        if u == BigUint::ZERO {
            return None;
        }
        let mut colon = Vec::new();
        if self.identity_in_x {
            colon.extend_from_slice(self.username.as_bytes());
        }
        colon.push(b':');
        colon.extend_from_slice(password);
        let x = BigUint::from_bytes_be(&sha256(&[salt, &sha256(&[&colon])]));
        let g = BigUint::from(2u8);
        let v = g.modpow(&x, &n);
        let base = (&b + &n - ((k_mult() * v) % &n)) % &n;
        let exp = &self.a + &u * &x;
        let s = base.modpow(&exp, &n);
        let k = sha256(&[&minimal(&s)]);
        let m1 = sha256(&[
            &h_n_xor_h_g(),
            &sha256(&[self.username.as_bytes()]),
            salt,
            &minimal(&self.big_a),
            &minimal(&b),
            &k,
        ]);
        self.expected_m2 = sha256(&[&minimal(&self.big_a), &m1, &k]).to_vec();
        self.key = Some(k);
        Some(m1.to_vec())
    }

    /// Checks the server proof; on a match the session key becomes available.
    pub fn verify_session(&mut self, server_m2: Option<&[u8]>) -> bool {
        let expected = &self.expected_m2;
        if expected.is_empty() {
            return false;
        }
        match server_m2 {
            Some(m2) if constant_time_eq(expected, m2) => {
                self.session_key = self.key;
                true
            }
            _ => false,
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

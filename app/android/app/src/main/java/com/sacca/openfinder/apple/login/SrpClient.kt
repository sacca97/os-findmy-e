package com.sacca.openfinder.apple.login

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * The client half of Apple's SRP-6a, exactly as `findmy.reports.account` drives pysrp (`srp._pysrp` with
 * `rfc5054_enable()` and `no_username_in_x()`, SHA-256, the RFC 5054 2048-bit group):
 *
 * ```
 * k  = H(N ‖ PAD(g))                       x  = H(s ‖ H(":" ‖ P))           (no username in x)
 * u  = H(PAD(A) ‖ PAD(B))                  S  = (B − k·g^x)^(a + u·x) mod N
 * K  = H(S)                                M1 = H((H(N) ⊕ H(PAD(g))) ‖ H(I) ‖ s ‖ A ‖ B ‖ K)
 * M2 = H(A ‖ M1 ‖ K)
 * ```
 *
 * Big integers are serialised minimally (no leading zero, no sign byte) everywhere except where PAD() says 256 bytes.
 *
 * **Deliberate fidelity to the Python over the spec:** `01-authentication.md` §4.6 ("deviation 2") says Apple hashes `u`
 * over unpadded A and B. pysrp in rfc5054 mode pads both, and that is what has authenticated every session so far. The two
 * only differ when A or B has a leading zero byte (about 1 time in 128); the oracle vectors cover both cases.
 *
 * @param a the secret ephemeral, big-endian. pysrp uses 256 random bytes with the top bit set ([randomEphemeral]).
 */
internal class SrpClient(private val username: String, a: ByteArray) {
    private val a = BigInteger(1, a)
    private val bigA: BigInteger = G.modPow(this.a, N)

    /** `A2k`: A, minimal big-endian. */
    val publicA: ByteArray = minimal(bigA)

    private var expectedM2: ByteArray? = null
    private var key: ByteArray? = null

    /** The session key K once the server proof has verified, else null (like pysrp's `get_session_key`). */
    var sessionKey: ByteArray? = null
        private set

    /** M1 for the server's salt and B, given the derived password P; null when the SRP-6a safety checks fail. */
    fun processChallenge(salt: ByteArray, serverB: ByteArray, password: ByteArray): ByteArray? {
        val b = BigInteger(1, serverB)
        if (b.mod(N).signum() == 0) return null
        val u = BigInteger(1, sha256(pad(minimal(bigA)), pad(minimal(b))))
        if (u.signum() == 0) return null
        val x = BigInteger(1, sha256(salt, sha256(byteArrayOf(':'.code.toByte()), password)))
        val v = G.modPow(x, N)
        val s = b.subtract(K_MULT.multiply(v)).mod(N).modPow(this.a.add(u.multiply(x)), N)
        val k = sha256(minimal(s))
        val m1 = sha256(HN_XOR_HG, sha256(username.toByteArray(Charsets.UTF_8)), salt, minimal(bigA), minimal(b), k)
        expectedM2 = sha256(minimal(bigA), m1, k)
        key = k
        return m1
    }

    /** Checks the server proof; on a match the session key becomes available. */
    fun verifySession(serverM2: ByteArray?): Boolean {
        val expected = expectedM2 ?: return false
        if (serverM2 == null || !MessageDigest.isEqual(expected, serverM2)) return false
        sessionKey = key
        return true
    }

    companion object {
        private val N = BigInteger(
            "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D" +
                "CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF" +
                "747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0" +
                "D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9" +
                "DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
            16,
        )
        private val G = BigInteger.valueOf(2)
        private val N_BYTES = minimal(N).size                       // 256

        private val K_MULT = BigInteger(1, sha256(minimal(N), pad(minimal(G))))
        private val HN_XOR_HG: ByteArray = sha256(minimal(N)).let { hn ->
            val hg = sha256(pad(minimal(G)))
            ByteArray(hn.size) { (hn[it].toInt() xor hg[it].toInt()).toByte() }
        }

        /** 256 random bytes with the top bit set, as pysrp's `get_random_of_length(256)`. */
        fun randomEphemeral(random: SecureRandom = SecureRandom()): ByteArray =
            ByteArray(256).also { random.nextBytes(it); it[0] = (it[0].toInt() or 0x80).toByte() }

        /** pysrp's `long_to_bytes`: big-endian with no leading zero bytes (zero is the empty string). */
        internal fun minimal(n: BigInteger): ByteArray {
            val raw = n.toByteArray()
            var i = 0
            while (i < raw.size && raw[i].toInt() == 0) i++
            return raw.copyOfRange(i, raw.size)
        }

        private fun pad(b: ByteArray): ByteArray = if (b.size >= N_BYTES) b else ByteArray(N_BYTES - b.size) + b

        private fun sha256(vararg parts: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-256").run { parts.forEach { update(it) }; digest() }
    }
}

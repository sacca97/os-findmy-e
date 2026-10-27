package com.sacca.openfinder.apple

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Calendar
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal

/** The Apple root is the one Python bundles (same SHA-256), it is added to (not substituted for) the platform's anchors, and the system decides first. */
class AppleTlsTest {
    private class FakeTrust(private val error: CertificateException?, private val issuers: Array<X509Certificate> = emptyArray()) : X509TrustManager {
        var serverChecks = 0
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) { serverChecks++; if (error != null) throw error }
        override fun getAcceptedIssuers() = issuers
    }

    private val chain = emptyArray<X509Certificate>()

    @Test fun bundledRootIsApplesRootCa() {
        val root = AppleTls.appleRoot
        assertEquals(X500Principal("CN=Apple Root CA, OU=Apple Certification Authority, O=Apple Inc., C=US"), root.subjectX500Principal)
        root.verify(root.publicKey)                                    // self-signed
        assertEquals("b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024", AppleTls.APPLE_ROOT_CA_SHA256)
        fun year(d: java.util.Date) = Calendar.getInstance().apply { time = d }.get(Calendar.YEAR)
        assertEquals(2006, year(root.notBefore)); assertEquals(2035, year(root.notAfter))
    }

    @Test fun aCertificateThatDoesNotHashToTheExpectedValueIsRefused() {
        val e = assertThrows(IllegalStateException::class.java) { AppleTls.verifiedRoot(expectedSha256 = "00".repeat(32)) }
        assertTrue(e.message!!.contains("refusing to trust"))
    }

    @Test fun aMangledOrNonCertificatePemIsRefused() {
        assertThrows(IllegalStateException::class.java) { AppleTls.verifiedRoot(pem = "not a certificate") }
        assertThrows(IllegalStateException::class.java) { AppleTls.verifiedRoot(pem = AppleTls.APPLE_ROOT_CA_PEM.replace("MIIEuzCCA6Og", "MIIEuzCCA6Oh")) }
    }

    @Test fun trustIsAdditive() {
        val issuers = AppleTls.trustManager.acceptedIssuers
        assertTrue(issuers.any { it == AppleTls.appleRoot })
        assertTrue("platform anchors are kept", issuers.size > 1)
    }

    @Test fun theSystemStoreDecidesFirstAndTheAppleRootIsOnlyAFallback() {
        val primary = FakeTrust(null); val extra = FakeTrust(CertificateException("extra must not be asked"))
        AppleTls.combine(primary, extra).checkServerTrusted(chain, "RSA")
        assertEquals(1, primary.serverChecks); assertEquals(0, extra.serverChecks)
    }

    @Test fun aChainRejectedBySystemButAcceptedByTheAppleRootIsTrusted() {
        val primary = FakeTrust(CertificateException("system: unknown root")); val extra = FakeTrust(null)
        AppleTls.combine(primary, extra).checkServerTrusted(chain, "RSA")
        assertEquals(1, extra.serverChecks)
    }

    @Test fun whenBothRejectTheSystemStoresErrorIsTheOneReported() {
        val first = CertificateException("system: unknown root")
        val e = assertThrows(CertificateException::class.java) {
            AppleTls.combine(FakeTrust(first), FakeTrust(CertificateException("apple: no path"))).checkServerTrusted(chain, "RSA")
        }
        assertSame(first, e)
    }

    @Test fun theSharedClientsAreBuiltFromIt() {
        AppleHttp.builder().build()
        val unpooled = AppleHttp.unpooled(AppleHttp.builder().build())
        assertEquals(listOf(okhttp3.Protocol.HTTP_1_1), unpooled.protocols)
    }
}

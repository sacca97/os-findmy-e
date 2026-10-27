package com.sacca.openfinder.apple

import okhttp3.OkHttpClient
import java.io.ByteArrayInputStream
import java.net.Socket
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager
import javax.net.ssl.X509TrustManager

/**
 * The trust store Apple's servers are verified against (port of `findmy.util.tls.apple_trust_context`): the platform's own
 * anchors **plus** Apple's 2006 "Apple Root CA", which `gsa.apple.com` chains to and which most stores lack. Adding an
 * anchor weakens nothing already there; verification stays on. The bundled root is checked against its SHA-256 before use.
 */
object AppleTls {
    /** Apple Root CA, serial 2, valid 2006-2035 (https://www.apple.com/appleca/). */
    internal const val APPLE_ROOT_CA_PEM = """-----BEGIN CERTIFICATE-----
MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0
MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw
bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+
+FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1
XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w
tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IW
q6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKM
aLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8E
BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3
R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAE
ggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93
d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNl
IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0
YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj
b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp
Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBc
NplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQP
y3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7
R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fg
xhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oP
IQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AX
UKqK1drk/NAJBzewdXUh
-----END CERTIFICATE-----
"""
    internal const val APPLE_ROOT_CA_SHA256 = "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"

    /** The bundled root, after checking it hashes to [APPLE_ROOT_CA_SHA256]. */
    val appleRoot: X509Certificate by lazy { verifiedRoot() }

    /** @throws IllegalStateException when [pem] is not a certificate that hashes to [expectedSha256] (a certificate is only an anchor once it does). */
    internal fun verifiedRoot(pem: String = APPLE_ROOT_CA_PEM, expectedSha256: String = APPLE_ROOT_CA_SHA256): X509Certificate {
        val cert = try {
            CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(pem.toByteArray(Charsets.US_ASCII))) as X509Certificate
        } catch (e: Exception) {
            throw IllegalStateException("The bundled Apple root is not a certificate")
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(cert.encoded).joinToString("") { "%02x".format(it) }
        check(digest == expectedSha256) { "The bundled Apple root hashes to $digest, not $expectedSha256; refusing to trust it" }
        return cert
    }

    /** The combination rule on its own, for tests: [first] decides; [second] is only asked when [first] rejects. */
    internal fun combine(first: X509TrustManager, second: X509TrustManager): X509TrustManager = CombinedTrustManager(first, second)

    /** Platform anchors first; a chain they reject is tried against Apple's root alone. */
    val trustManager: X509TrustManager by lazy {
        val platform = trustManagerFor(null)
        val apple = trustManagerFor(KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry("apple-root-ca", appleRoot)
        })
        CombinedTrustManager(platform, apple)
    }

    /** [builder] with the combined trust store. Hostname verification is OkHttp's own and unchanged. */
    fun apply(builder: OkHttpClient.Builder): OkHttpClient.Builder {
        val context = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustManager), null) }
        return builder.sslSocketFactory(context.socketFactory, trustManager)
    }

    private fun trustManagerFor(store: KeyStore?): X509TrustManager =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).run {
            init(store)
            trustManagers.filterIsInstance<X509TrustManager>().first()
        }

    /**
     * Accepts a chain either delegate accepts. Extended (socket/engine-aware) calls are passed through where the delegate
     * supports them, so a platform manager that needs the hostname (Android's network-security config) gets it.
     */
    private class CombinedTrustManager(private val first: X509TrustManager, private val second: X509TrustManager) : X509ExtendedTrustManager() {
        private inline fun either(a: () -> Unit, b: () -> Unit) {
            try { a() } catch (e: CertificateException) {
                try { b() } catch (_: CertificateException) { throw e }
            }
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) =
            either({ first.checkServerTrusted(chain, authType) }, { second.checkServerTrusted(chain, authType) })

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, socket: Socket?) = either(
            { (first as? X509ExtendedTrustManager)?.checkServerTrusted(chain, authType, socket) ?: first.checkServerTrusted(chain, authType) },
            { (second as? X509ExtendedTrustManager)?.checkServerTrusted(chain, authType, socket) ?: second.checkServerTrusted(chain, authType) },
        )

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine?) = either(
            { (first as? X509ExtendedTrustManager)?.checkServerTrusted(chain, authType, engine) ?: first.checkServerTrusted(chain, authType) },
            { (second as? X509ExtendedTrustManager)?.checkServerTrusted(chain, authType, engine) ?: second.checkServerTrusted(chain, authType) },
        )

        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = first.checkClientTrusted(chain, authType)
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, socket: Socket?) = first.checkClientTrusted(chain, authType)
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine?) = first.checkClientTrusted(chain, authType)
        override fun getAcceptedIssuers(): Array<X509Certificate> = first.acceptedIssuers + second.acceptedIssuers
    }
}

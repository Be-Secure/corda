package net.corda.nodeapi.internal.revocation

import com.github.benmanes.caffeine.cache.Caffeine
import com.github.benmanes.caffeine.cache.LoadingCache
import net.corda.core.internal.readFully
import net.corda.core.utilities.seconds
import net.corda.nodeapi.internal.crypto.X509CertificateFactory
import net.corda.nodeapi.internal.protonwrapper.netty.CrlSource
import net.corda.nodeapi.internal.protonwrapper.netty.distributionPoints
import java.net.URL
import java.security.cert.X509CRL
import java.security.cert.X509Certificate

/**
 * [CrlSource] which downloads CRLs from the distribution points in the X509 certificate.
 */
object CertDistPointCrlSource : CrlSource {
    private const val DEFAULT_CONNECT_TIMEOUT = 60_000
    private const val DEFAULT_READ_TIMEOUT = 60_000

    private val cache: LoadingCache<URL, X509CRL> = Caffeine.newBuilder()
            .expireAfterWrite(30.seconds)  // Mimick the 30s cache expiry behaviour of the JDK (URICertStore.engineGetCRLs)
            .build(::retrieveCrl)

    private fun retrieveCrl(url: URL): X509CRL {
        val bytes = run {
            val conn = url.openConnection()
            conn.connectTimeout = Integer.getInteger("net.corda.crl.connectTimeoutMs", DEFAULT_CONNECT_TIMEOUT)
            conn.readTimeout = Integer.getInteger("net.corda.crl.readTimeoutMs", DEFAULT_READ_TIMEOUT)
            // Read all bytes first and then pass them into the CertificateFactory. This may seem unnecessary when generateCRL already takes
            // in an InputStream, but the JDK implementation (sun.security.provider.X509Factory.engineGenerateCRL) converts any IOException
            // into CRLException and drops the cause chain.
            conn.getInputStream().readFully()
        }
        return X509CertificateFactory().generateCRL(bytes.inputStream())
    }

    /**
     * Retrieve the CRL for a X509 certificate
     */
    override fun fetch(certificate: X509Certificate): Set<X509CRL> {
        val crls = HashSet<X509CRL>()
        var exception: Exception? = null
        for (distPoint in certificate.distributionPoints()) {
            try {
                crls += cache[URL(distPoint)]!!
            } catch (e: Exception) {
                if (exception == null) {
                    exception = e
                } else {
                    exception.addSuppressed(e)
                }
            }
        }
        // Only throw if no CRLs are retrieved
        if (exception != null && crls.isEmpty()) {
            throw exception
        } else {
            return crls
        }
    }
}

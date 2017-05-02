package net.corda.core.crypto

import net.i2p.crypto.eddsa.EdDSAEngine
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.OutputStream
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature

/**
 *  Provide extra OID look up for signature algorithm not supported by bouncy castle.
 *  This builder will use bouncy castle's JcaContentSignerBuilder as fallback for unknown algorithm.
 */
object ContentSignerBuilder {
    private val additionalAlgorithms: Map<String, AlgorithmIdentifier> = mapOf(
            // OId for Ed25519 EdDSA signature scheme, see 'https://tools.ietf.org/id/draft-ietf-ipsecme-eddsa-01.html#oid_ed25519' for more information.
            EdDSAEngine.SIGNATURE_ALGORITHM to AlgorithmIdentifier(ASN1ObjectIdentifier("1.3.101.112"))
    )

    fun build(signatureAlgorithm: String, privateKey: PrivateKey, provider: String, random: SecureRandom? = null): ContentSigner {
        val sigAlgId = additionalAlgorithms[signatureAlgorithm]
        return if (sigAlgId != null) {
            val sig = Signature.getInstance(signatureAlgorithm, provider).apply {
                if (random != null) {
                    initSign(privateKey, random)
                } else {
                    initSign(privateKey)
                }
            }
            return object : ContentSigner {
                private val stream = SignatureOutputStream(sig)
                override fun getAlgorithmIdentifier(): AlgorithmIdentifier = sigAlgId
                override fun getOutputStream(): OutputStream = stream
                override fun getSignature(): ByteArray = stream.signature
            }
        } else {
            // Delegate to bouncy castle's content signer builder as fallback.
            val jcaBuilder = JcaContentSignerBuilder(signatureAlgorithm).setProvider(provider)
            if (random != null) {
                jcaBuilder.setSecureRandom(random)
            }
            jcaBuilder.build(privateKey)
        }
    }

    private class SignatureOutputStream(private val sig: Signature) : OutputStream() {
        internal val signature: ByteArray get() = sig.sign()
        override fun write(bytes: ByteArray, off: Int, len: Int) = sig.update(bytes, off, len)
        override fun write(bytes: ByteArray) = sig.update(bytes)
        override fun write(b: Int) = sig.update(b.toByte())
    }
}

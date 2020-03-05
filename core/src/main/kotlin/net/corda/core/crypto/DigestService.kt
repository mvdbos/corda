package net.corda.core.crypto

import net.corda.core.DeleteForDJVM
import org.bouncycastle.jcajce.provider.digest.Blake2b

interface DigestService {
    /**
     * The length of the digest in bytes
     */
    val digestLength: Int

    /**
     * Computes the digest of the [ByteArray].
     *
     * @param bytes The [ByteArray] to hash.
     */
    fun hash(bytes: ByteArray, lengthExtensionResistant: Boolean = false): SecureHash

    /**
     * Computes the digest of the [String]'s UTF-8 byte contents.
     *
     * @param str [String] whose UTF-8 contents will be hashed.
     */
    fun hash(str: String, lengthExtensionResistant: Boolean = false): SecureHash

    /**
     * A digest value consisting of [digestLength] 0xFF bytes.
     *
     * TODO: These seem to be also mostly used for testing? I see only two other places?
     */
    val allOnesHash: SecureHash

    /**
     * A hash value consisting of [digestLength] 0x00 bytes.
     */
    val zeroHash: SecureHash
}

class SHA256Service() : DigestService {
    override val digestLength = 32

    override fun hash(bytes: ByteArray, lengthExtensionResistant: Boolean) = if (lengthExtensionResistant) SecureHash.sha256(SecureHash.sha256(bytes).bytes) else SecureHash.Companion.sha256(bytes)

    override fun hash(str: String, lengthExtensionResistant: Boolean): SecureHash = hash(str.toByteArray(), lengthExtensionResistant)

    override val allOnesHash = SecureHash.allOnesHash

    override val zeroHash = SecureHash.zeroHash
}

class BLAKE2b256Service : DigestService {
    private val blake2b256 = Blake2b.Blake2b256()

    override val digestLength: Int by lazy { blake2b256.digestLength }

    /**
     * BLAKE2b256 is resistant to length extension attack, so no double hashing needed. We ignore the parameter.
     */
    override fun hash(bytes: ByteArray, lengthExtensionResistant: Boolean) = SecureHash.BLAKE2b256(blake2b256.digest(bytes))

    override fun hash(str: String, lengthExtensionResistant: Boolean): SecureHash = hash(str.toByteArray(), lengthExtensionResistant)

    override val allOnesHash = SecureHash.BLAKE2b256(ByteArray(digestLength) { 255.toByte() })

    override val zeroHash = SecureHash.BLAKE2b256(ByteArray(digestLength) { 0.toByte() })
}

/**
 * For testing only
 */
@DeleteForDJVM
fun SHA256Service.random() = SecureHash.randomSHA256()
@DeleteForDJVM
fun BLAKE2b256Service.random() = SecureHash.BLAKE2b256(secureRandomBytes(32))



package net.corda.core.crypto

import net.corda.core.crypto.SecureHash.SHA384
import java.security.MessageDigest

interface DigestService {
    /**
     * Computes the SHA-384 hash value of the [ByteArray].
     * @param bytes The [ByteArray] to hash.
     */
    fun hash(bytes: ByteArray): SecureHash

    /**
     * Computes the SHA-384 hash of the [String]'s UTF-8 byte contents.
     * @param str [String] whose UTF-8 contents will be hashed.
     */
    fun hash(str: String): SecureHash

    /**
     * A SHA-384 hash value consisting of [SHA384.DIGEST_LENGTH] 0xFF bytes.
     *
     * TODO: These seem to be also mostly used for testing? I see only two other places?
     */
    fun getAllOnesHash(): SecureHash

    /**
     * A SHA-384 hash value consisting of [SHA384.DIGEST_LENGTH] 0x00 bytes.
     */
    fun getZeroHash(): SecureHash

    /**
     * Generates a random SHA-384 value.
     *
     * TODO: Should this even be in here? It seems to be only used for testing
     */
    fun random(): SecureHash
}

class SHA256Service() : DigestService {
    override fun hash(bytes: ByteArray) = SecureHash.SHA256(MessageDigest.getInstance("SHA-256").digest(bytes))

    override fun hash(str: String) = hash(str.toByteArray())

    override fun getAllOnesHash() = SecureHash.SHA256(ByteArray(SecureHash.SHA256.DIGEST_LENGTH) { 255.toByte() })

    override fun getZeroHash() = SecureHash.SHA256(ByteArray(SecureHash.SHA256.DIGEST_LENGTH) { 0.toByte() })

    override fun random() = hash(secureRandomBytes(SecureHash.SHA256.DIGEST_LENGTH))
}

class SHA384Service() : DigestService {
    override fun hash(bytes: ByteArray) = SecureHash.SHA384(MessageDigest.getInstance("SHA-384").digest(bytes))

    override fun hash(str: String) = hash(str.toByteArray())

    override fun getAllOnesHash() = SecureHash.SHA384(ByteArray(SecureHash.SHA384.DIGEST_LENGTH) { 255.toByte() })

    override fun getZeroHash() = SecureHash.SHA384(ByteArray(SecureHash.SHA384.DIGEST_LENGTH) { 0.toByte() })

    override fun random() = hash(secureRandomBytes(SecureHash.SHA384.DIGEST_LENGTH))
}



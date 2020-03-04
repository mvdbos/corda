package net.corda.core.crypto

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
    fun hash(bytes: ByteArray): SecureHash

    /**
     * Computes the digest of the [String]'s UTF-8 byte contents.
     *
     * @param str [String] whose UTF-8 contents will be hashed.
     */
    fun hash(str: String): SecureHash

    /**
     * A digest value consisting of [digestLength] 0xFF bytes.
     *
     * TODO: These seem to be also mostly used for testing? I see only two other places?
     */
    fun getAllOnesHash(): SecureHash

    /**
     * A hash value consisting of [digestLength] 0x00 bytes.
     */
    fun getZeroHash(): SecureHash
}

class SHA256Service() : DigestService {
    override val digestLength: Int
        get() = 32

    override fun hash(bytes: ByteArray) = SecureHash.sha256(bytes)

    override fun hash(str: String) = hash(str.toByteArray())

    override fun getAllOnesHash() = SecureHash.allOnesHash

    override fun getZeroHash() = SecureHash.zeroHash
}

/**
 * For testing only
 */
fun SHA256Service.random() = SecureHash.randomSHA256()



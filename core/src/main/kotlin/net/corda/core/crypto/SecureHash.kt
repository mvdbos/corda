@file:KeepForDJVM

package net.corda.core.crypto

import io.netty.util.concurrent.FastThreadLocal
import net.corda.core.DeleteForDJVM
import net.corda.core.KeepForDJVM
import net.corda.core.serialization.CordaSerializable
import net.corda.core.utilities.OpaqueBytes
import net.corda.core.utilities.parseAsHex
import net.corda.core.utilities.toHexString
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.function.Supplier

/**
 * Container for a cryptographically secure hash value.
 * Provides utilities for generating a cryptographic hash using different algorithms (currently only SHA-256 supported).
 */
@KeepForDJVM
@CordaSerializable
sealed class SecureHash(bytes: ByteArray) : OpaqueBytes(bytes) {
    /** SHA-384 is part of the SHA-2 hash function family. Generated hash is size [SHA384.DIGEST_LENGTH]. */
    class SHA384(bytes: ByteArray) : SecureHash(bytes) {

        init {
            require(bytes.size == DIGEST_LENGTH) { "Invalid hash size, must be $DIGEST_LENGTH bytes" }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            if (!super.equals(other)) return false
            return true
        }

        // This is an efficient hashCode, because there is no point in performing a hash calculation on a cryptographic hash.
        // It just takes the first 4 bytes and transforms them into an Int.
        override fun hashCode() = ByteBuffer.wrap(bytes).int

        companion object {
            const val DIGEST_LENGTH = 48
        }
    }

    /** SHA-256 is part of the SHA-2 hash function family. Generated hash is size [SHA256.DIGEST_LENGTH]. */
    class SHA256(bytes: ByteArray) : SecureHash(bytes) {

        init {
            require(bytes.size == DIGEST_LENGTH) { "Invalid hash size, must be $DIGEST_LENGTH bytes" }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            if (!super.equals(other)) return false
            return true
        }

        // This is an efficient hashCode, because there is no point in performing a hash calculation on a cryptographic hash.
        // It just takes the first 4 bytes and transforms them into an Int.
        override fun hashCode() = ByteBuffer.wrap(bytes).int

        companion object {
            const val DIGEST_LENGTH = 32
        }
    }

    inline fun <reified T : SecureHash> hashConcat(other: T): T {
        return when (this) {
            is SHA256 -> (this.bytes + other.bytes).sha256() as T
            is SHA384 -> (this.bytes + other.bytes).sha384() as T
        }
    }

    /**
     * Convert the hash value to an uppercase hexadecimal [String].
     */
    override fun toString(): String = bytes.toHexString()

    /**
     * Returns the first [prefixLen] hexadecimal digits of the [SecureHash] value.
     * @param prefixLen The number of characters in the prefix.
     */
    fun prefixChars(prefixLen: Int = 6) = toString().substring(0, prefixLen)

    // Like static methods in Java, except the 'companion' is a singleton that can have state.
    companion object {
        /**
         * Converts a SHA-256 hash value represented as a hexadecimal [String] into a [SecureHash].
         * @param str A sequence of 64 hexadecimal digits that represents a SHA-256 hash value.
         * @throws IllegalArgumentException The input string does not contain 64 hexadecimal digits, or it contains incorrectly-encoded characters.
         */
        @JvmStatic
        fun parse(str: String?): SecureHash {
            return str?.toUpperCase()?.parseAsHex()?.let {
                when (it.size) {
                    SHA384.DIGEST_LENGTH -> SHA384(it)
                    SHA256.DIGEST_LENGTH -> SHA256(it)
                    else -> throw IllegalArgumentException("Provided string is ${it.size} bytes. Should be either $SHA256.DIGEST_LENGTH or $SHA384.DIGEST_LENGTH bytes in hex: $str")
                }
            } ?: throw IllegalArgumentException("Provided string is null")
        }

        /** BEGIN SHA-256 **/

        /**
         * Computes the SHA-256 hash value of the [ByteArray].
         * @param bytes The [ByteArray] to hash.
         */
        @JvmStatic
        fun sha256(bytes: ByteArray) = SHA256(SHA256DigestSupplier().get().digest(bytes))

        /**
         * Computes the SHA-256 hash of the [ByteArray], and then computes the SHA-256 hash of the hash.
         * @param bytes The [ByteArray] to hash.
         */
        @JvmStatic
        fun sha256Twice(bytes: ByteArray) = sha256(sha256(bytes).bytes)

        /**
         * Computes the SHA-256 hash of the [String]'s UTF-8 byte contents.
         * @param str [String] whose UTF-8 contents will be hashed.
         */
        @JvmStatic
        fun sha256(str: String) = sha256(str.toByteArray())

        /**
         * Generates a random SHA-256 value.
         */
        @DeleteForDJVM
        @JvmStatic
        fun randomSHA256() = sha256(secureRandomBytes(SHA384.DIGEST_LENGTH))

        /**
         * A SHA-256 hash value consisting of [SHA384.DIGEST_LENGTH] 0x00 bytes.
         * This field provides more intuitive access from Java.
         */
        @JvmField
        val zeroHash: SHA256 = SHA256(ByteArray(SHA256.DIGEST_LENGTH) { 0.toByte() })

        /**
         * A SHA-256 hash value consisting of [SHA384.DIGEST_LENGTH] 0x00 bytes.
         * This function is provided for API stability.
         */
        @Suppress("Unused")
        fun getZeroHash(): SHA256 = zeroHash

        /**
         * A SHA-256 hash value consisting of [SHA384.DIGEST_LENGTH] 0xFF bytes.
         * This field provides more intuitive access from Java.
         */
        @JvmField
        val allOnesHash: SHA256 = SHA256(ByteArray(SHA256.DIGEST_LENGTH) { 255.toByte() })

        /**
         * A SHA-256 hash value consisting of [SHA384.DIGEST_LENGTH] 0xFF bytes.
         * This function is provided for API stability.
         */
        @Suppress("Unused")
        fun getAllOnesHash(): SHA256 = allOnesHash

        /** END SHA-256 **/

        /** BEGIN SHA-384 **/

        /**
         * Computes the SHA-384 hash value of the [ByteArray].
         * @param bytes The [ByteArray] to hash.
         */
        @JvmStatic
        fun sha384(bytes: ByteArray) = SHA384(SHA384DigestSupplier().get().digest(bytes))

        /**
         * Computes the SHA-384 hash of the [ByteArray], and then computes the SHA-384 hash of the hash.
         * @param bytes The [ByteArray] to hash.
         */
        @JvmStatic
        fun sha384Twice(bytes: ByteArray) = sha384(sha384(bytes).bytes)

        /**
         * Computes the SHA-384 hash of the [String]'s UTF-8 byte contents.
         * @param str [String] whose UTF-8 contents will be hashed.
         */
        @JvmStatic
        fun sha384(str: String) = sha384(str.toByteArray())

        /**
         * Generates a random SHA-384 value.
         */
        @DeleteForDJVM
        @JvmStatic
        fun randomSHA384() = sha384(secureRandomBytes(SHA384.DIGEST_LENGTH))

        /**
         * A SHA-384 hash value consisting of [SHA384.DIGEST_LENGTH] 0x00 bytes.
         * This field provides more intuitive access from Java.
         */
        @JvmField
        val zeroHash384: SHA384 = SHA384(ByteArray(SHA384.DIGEST_LENGTH) { 0.toByte() })

        /**
         * A SHA-384 hash value consisting of [SHA384.DIGEST_LENGTH] 0x00 bytes.
         * This function is provided for API stability.
         */
        @Suppress("Unused")
        fun getZeroHash384(): SHA384 = zeroHash384

        /**
         * A SHA-384 hash value consisting of [SHA384.DIGEST_LENGTH] 0xFF bytes.
         * This field provides more intuitive access from Java.
         */
        @JvmField
        val allOnesHash384: SHA384 = SHA384(ByteArray(SHA384.DIGEST_LENGTH) { 255.toByte() })

        /**
         * A SHA-384 hash value consisting of [SHA384.DIGEST_LENGTH] 0xFF bytes.
         * This function is provided for API stability.
         */
        @Suppress("Unused")
        fun getAllOnesHash384(): SHA384 = allOnesHash384

        /** END SHA-384 **/
    }
}

/**
 * Compute the SHA-256 hash for the contents of the [ByteArray].
 */
fun ByteArray.sha256(): SecureHash.SHA256 = SecureHash.sha256(this)

/**
 * Compute the SHA-256 hash for the contents of the [OpaqueBytes].
 */
fun OpaqueBytes.sha256(): SecureHash.SHA256 = SecureHash.sha256(this.bytes)

/**
 * Compute the SHA-384 hash for the contents of the [ByteArray].
 */
fun ByteArray.sha384(): SecureHash.SHA384 = SecureHash.sha384(this)

/**
 * Compute the SHA-384 hash for the contents of the [OpaqueBytes].
 */
fun OpaqueBytes.sha384(): SecureHash.SHA384 = SecureHash.sha384(this.bytes)

/**
 * Hide the [FastThreadLocal] class behind a [Supplier] interface
 * so that we can remove it for core-deterministic.
 */
private class SHA384DigestSupplier : Supplier<MessageDigest> {
    private val threadLocalSha384MessageDigest = LocalSHA384Digest()
    override fun get(): MessageDigest = threadLocalSha384MessageDigest.get()
}

// Declaring this as "object : FastThreadLocal<>" would have
// created an extra public class in the API definition.
private class LocalSHA384Digest : FastThreadLocal<MessageDigest>() {
    override fun initialValue(): MessageDigest = MessageDigest.getInstance("SHA-384")
}

/**
 * Hide the [FastThreadLocal] class behind a [Supplier] interface
 * so that we can remove it for core-deterministic.
 */
private class SHA256DigestSupplier : Supplier<MessageDigest> {
    private val threadLocalSha256MessageDigest = LocalSHA256Digest()
    override fun get(): MessageDigest = threadLocalSha256MessageDigest.get()
}

// Declaring this as "object : FastThreadLocal<>" would have
// created an extra public class in the API definition.
private class LocalSHA256Digest : FastThreadLocal<MessageDigest>() {
    override fun initialValue(): MessageDigest = MessageDigest.getInstance("SHA-256")
}

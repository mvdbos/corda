package net.corda.deterministic.contracts

import net.corda.core.contracts.PrivacySalt
import net.corda.core.crypto.SecureHash.SHA384
import org.junit.Test
import kotlin.test.*

class PrivacySaltTest {
    private companion object {
        private val SALT_SIZE = SHA384.DIGEST_LENGTH
    }

    @Test(timeout=300_000)
	fun testValidSalt() {
        PrivacySalt(ByteArray(SALT_SIZE) { 0x14 })
    }

    @Test(timeout=300_000)
	fun testInvalidSaltWithAllZeros() {
        val ex = assertFailsWith<IllegalArgumentException> { PrivacySalt(ByteArray(SALT_SIZE)) }
        assertEquals("Privacy salt should not be all zeros.", ex.message)
    }

    @Test(timeout=300_000)
	fun testTooShortPrivacySalt() {
        val ex = assertFailsWith<IllegalArgumentException> { PrivacySalt(ByteArray(SALT_SIZE - 1) { 0x7f }) }
        assertEquals("Privacy salt should be $SALT_SIZE bytes.", ex.message)
    }

    @Test(timeout=300_000)
	fun testTooLongPrivacySalt() {
        val ex = assertFailsWith<IllegalArgumentException> { PrivacySalt(ByteArray(SALT_SIZE + 1) { 0x7f }) }
        assertEquals("Privacy salt should be $SALT_SIZE bytes.", ex.message)
    }
}
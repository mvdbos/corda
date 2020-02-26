package net.corda.core.contracts

import net.corda.core.crypto.SecureHash
import org.assertj.core.api.Assertions.assertThatExceptionOfType
import org.junit.Test

class PrivacySaltTest {
    @Test(timeout=300_000)
	fun `all-zero PrivacySalt not allowed`() {
        assertThatExceptionOfType(IllegalArgumentException::class.java).isThrownBy {
            PrivacySalt(ByteArray(SecureHash.sha384DigestLength))
        }.withMessage("Privacy salt should not be all zeros.")
    }
}
package net.corda.core.transactions

import net.corda.core.crypto.SecureHash

/**
 * Implemented by all transactions. This merkle root is an additional identifier to [NamedByHash.id].
 *
 */
interface NamedByAdditionalMerkleRoot {
    /**
     * A [SecureHash] that identifies this transaction.
     *
     * This identifier is an additional merkle root of this transaction.
     * This enables flexibility in using additional, potentially less trusted algorithms for calculating this root.
     */
    val additionalMerkleRoot: SecureHash
}

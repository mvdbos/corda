package net.corda.core.transactions

import net.corda.core.CordaException
import net.corda.core.KeepForDJVM
import net.corda.core.contracts.ComponentGroupEnum
import net.corda.core.crypto.SecureHash
import net.corda.core.serialization.CordaSerializable
import net.corda.core.transactions.FilteredTransaction

@KeepForDJVM
@CordaSerializable
class ZKFilteredTransaction(val proof: ByteArray, private val ftx: FilteredTransaction) : TraversableTransaction(ftx.filteredComponentGroups) {
    override val id: SecureHash = ftx.id

    @Throws(ZKFilteredTransactionVerificationException::class)
    fun verify() {
        // Check that the merkle tree of the ftx is correct
        ftx.verify()

        // If the merkle tree is correct, confirm that the required components are visible
        ftx.checkAllComponentsVisible(ComponentGroupEnum.INPUTS_GROUP)
        ftx.checkAllComponentsVisible(ComponentGroupEnum.TIMEWINDOW_GROUP)
        ftx.checkAllComponentsVisible(ComponentGroupEnum.REFERENCES_GROUP)
        ftx.checkAllComponentsVisible(ComponentGroupEnum.PARAMETERS_GROUP)

        // TODO: verify the proof
        // proof.verify()
        // throw ZKFilteredTransactionVerificationException(ftx.id, "Not yet implemented")
    }
}

/** Thrown when [ZKFilteredTransaction.verify] fails.
 * @param id transaction's id.
 * @param reason information about the exception.
 */
@KeepForDJVM
@CordaSerializable
class ZKFilteredTransactionVerificationException(val id: SecureHash, val reason: String) : CordaException("Transaction with id:$id cannot be verified. Reason: $reason")

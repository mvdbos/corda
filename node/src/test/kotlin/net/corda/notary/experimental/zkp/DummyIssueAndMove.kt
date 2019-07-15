package net.corda.notary.experimental.zkp

import co.paralleluniverse.fibers.Suspendable
import net.corda.core.contracts.ContractState
import net.corda.core.contracts.TimeWindow
import net.corda.core.flows.FlowLogic
import net.corda.core.flows.StartableByRPC
import net.corda.core.identity.Party
import net.corda.core.transactions.SignedTransaction
import net.corda.core.transactions.TransactionBuilder

@StartableByRPC
class DummyIssueAndMove(private val notary: Party, private val counterpartyNode: Party, private val discriminator: Int, private val timeWindow: TimeWindow? = null) : FlowLogic<SignedTransaction>() {
    @Suspendable
    override fun call(): SignedTransaction {
        // Self issue an asset
        val state = DummyState(listOf(ourIdentity), discriminator)
        val issueTx = serviceHub.signInitialTransaction(TransactionBuilder(notary).apply {
            addOutputState(state, DO_NOTHING_PROGRAM_ID)
            addCommand(DummyCommand(), listOf(ourIdentity.owningKey))
        })
        serviceHub.recordTransactions(issueTx)
        // Move ownership of the asset to the counterparty
        // We don't check signatures because we know that the notary's signature is missing
        return serviceHub.signInitialTransaction(TransactionBuilder(notary).apply {
            addInputState(issueTx.tx.outRef<ContractState>(0))
            addOutputState(state.copy(participants = listOf(counterpartyNode)), DO_NOTHING_PROGRAM_ID)
            addCommand(DummyCommand(), listOf(ourIdentity.owningKey))
            if (timeWindow != null) {
                setTimeWindow(timeWindow)
            }
        })
    }
}

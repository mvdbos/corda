package net.corda.node.services

import net.corda.core.contracts.DummyContract
import net.corda.core.contracts.StateAndRef
import net.corda.core.contracts.StateRef
import net.corda.core.contracts.TransactionType
import net.corda.core.crypto.Party
import net.corda.core.div
import net.corda.core.getOrThrow
import net.corda.core.node.services.ServiceInfo
import net.corda.core.node.services.ServiceType
import net.corda.core.utilities.ALICE
import net.corda.flows.NotaryError
import net.corda.flows.NotaryException
import net.corda.flows.NotaryFlow
import net.corda.node.internal.AbstractNode
import net.corda.node.internal.Node
import net.corda.node.services.transactions.BFTNonValidatingNotaryService
import net.corda.node.utilities.ServiceIdentityGenerator
import net.corda.node.utilities.transaction
import net.corda.testing.node.NodeBasedTest
import org.bouncycastle.asn1.x500.X500Name
import org.junit.Test
import java.security.KeyPair
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class BFTNotaryServiceTests : NodeBasedTest() {
    private companion object {
        val notaryCommonName = "BFT Notary Server"
        val notaryPath = "BFT Notary Server"
        val notaryLegalName = X500Name("CN=${notaryCommonName},${notaryPath}")
    }

    @Test
    fun `detect double spend`() {
        val masterNode = startBFTNotaryCluster(notaryCommonName, notaryPath, 4, BFTNonValidatingNotaryService.type).first()
        val alice = startNode(ALICE.name).getOrThrow()

        val notaryParty = alice.netMapCache.getNotary(notaryLegalName)!!
        val notaryNodeKeyPair = with(masterNode) { database.transaction { services.notaryIdentityKey } }
        val aliceKey = with(alice) { database.transaction { services.legalIdentityKey } }

        val inputState = issueState(alice, notaryParty, notaryNodeKeyPair)

        val firstSpendTx = TransactionType.General.Builder(notaryParty).withItems(inputState).run {
            signWith(aliceKey)
            toSignedTransaction(false)
        }

        val firstSpend = alice.services.startFlow(NotaryFlow.Client(firstSpendTx))
        firstSpend.resultFuture.getOrThrow()

        val secondSpendTx = TransactionType.General.Builder(notaryParty).withItems(inputState).run {
            val dummyState = DummyContract.SingleOwnerState(0, alice.info.legalIdentity.owningKey)
            addOutputState(dummyState)
            signWith(aliceKey)
            toSignedTransaction(false)
        }
        val secondSpend = alice.services.startFlow(NotaryFlow.Client(secondSpendTx))

        val ex = assertFailsWith(NotaryException::class) { secondSpend.resultFuture.getOrThrow() }
        val error = ex.error as NotaryError.Conflict
        assertEquals(error.txId, secondSpendTx.id)
    }

    private fun issueState(node: AbstractNode, notary: Party, notaryKey: KeyPair): StateAndRef<*> {
        return node.database.transaction {
            val tx = DummyContract.generateInitial(Random().nextInt(), notary, node.info.legalIdentity.ref(0))
            tx.signWith(node.services.legalIdentityKey)
            tx.signWith(notaryKey)
            val stx = tx.toSignedTransaction()
            node.services.recordTransactions(listOf(stx))
            StateAndRef(tx.outputStates().first(), StateRef(stx.id, 0))
        }
    }

    private fun startBFTNotaryCluster(notaryCommonName: String,
                                      notaryPath: String,
                                      clusterSize: Int,
                                      serviceType: ServiceType): List<Node> {
        require(clusterSize > 0)
        val notaryName = X500Name("CN=${notaryCommonName},${notaryPath}")
        val quorum = (2 * clusterSize + 1) / 3
        ServiceIdentityGenerator.generateToDisk(
                (0 until clusterSize).map { tempFolder.root.toPath() / "$notaryName-$it" },
                serviceType.id,
                notaryName,
                quorum)

        val serviceInfo = ServiceInfo(serviceType, notaryName)
        val nodes = (0 until clusterSize).map {
            startNode(
                    X500Name("CN=$notaryCommonName-$it,${notaryPath}"),
                    advertisedServices = setOf(serviceInfo),
                    configOverrides = mapOf("notaryNodeId" to it)
            ).getOrThrow()
        }

        return nodes
    }
}

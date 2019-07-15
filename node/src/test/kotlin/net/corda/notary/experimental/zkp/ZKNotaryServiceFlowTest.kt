package net.corda.notary.experimental.zkp

import net.corda.core.crypto.TransactionSignature
import net.corda.core.flows.ZKNotaryFlow
import net.corda.core.identity.CordaX500Name
import net.corda.core.identity.Party
import net.corda.core.transactions.SignedTransaction
import net.corda.core.utilities.getOrThrow
import net.corda.testing.common.internal.testNetworkParameters
import net.corda.testing.core.singleIdentity
import net.corda.testing.node.MockNetwork
import net.corda.testing.node.MockNetworkNotarySpec
import net.corda.testing.node.MockNetworkParameters
import net.corda.testing.node.StartedMockNode
import net.corda.testing.node.internal.cordappWithPackages
import org.junit.After
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import kotlin.test.assertTrue

class ZKNotaryServiceTest {
    private lateinit var mockNet: MockNetwork
    private lateinit var notaryNode: StartedMockNode
    private lateinit var megaCorpNode: StartedMockNode
    private lateinit var miniCorpNode: StartedMockNode
    private lateinit var notary: Party
    private lateinit var megaCorp: Party
    private lateinit var miniCorp: Party

    @Before
    fun setup() {
        mockNet = MockNetwork(
                MockNetworkParameters(
                        cordappsForAllNodes = listOf(cordappWithPackages("net.corda.notary.experimental.zkp")),
                        networkParameters = testNetworkParameters(minimumPlatformVersion = 4),
                        notarySpecs = listOf(
                                MockNetworkNotarySpec(
                                        name = CordaX500Name("ZK Notary", "Amsterdam", "NL"),
                                        validating = false,
                                        className = "net.corda.notary.experimental.zkp.ZKNotaryService"

                                )
                        )
                )
        )

        notaryNode = mockNet.defaultNotaryNode

        megaCorpNode = mockNet.createPartyNode(CordaX500Name("MegaCorp", "Amsterdam", "NL"))
        miniCorpNode = mockNet.createPartyNode(CordaX500Name("MiniCorp", "London", "GB"))

        notary = notaryNode.info.singleIdentity()
        megaCorp = megaCorpNode.info.singleIdentity()
        miniCorp = miniCorpNode.info.singleIdentity()
    }

    @After
    fun tearDown() {
        mockNet.stopNodes()
    }

    @Test
    fun `notarise ZK`() {
        val txSigs = notariseZKTransaction(buildSignedTransaction())
        assertTrue("should be signed by the known ZK notary") { txSigs.any { it.by == notary.owningKey } }
    }

    @Test
    @Ignore
    fun `detect double spend`() {
        throw NotImplementedError()
    }

    private fun notariseZKTransaction(stx: SignedTransaction): List<TransactionSignature> {
        val future = miniCorpNode.startFlow(ZKNotaryFlow.Client(stx))
        mockNet.runNetwork()
        return future.getOrThrow()
    }

    /**
     * The party first self-issues a state (asset) and builds a transaction to transfer the asset to the counterparty.
     * The *move* transaction requires notarisation, as it consumes the original asset and creates a copy with
     * the new owner as its output.
     */
    private fun buildSignedTransaction(discriminator: Int = 1): SignedTransaction {
        val future = miniCorpNode.startFlow(DummyIssueAndMove(notary, megaCorp, discriminator))
        mockNet.runNetwork()
        return future.getOrThrow()
    }
}
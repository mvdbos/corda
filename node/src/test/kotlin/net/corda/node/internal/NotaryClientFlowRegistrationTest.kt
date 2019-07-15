package net.corda.node.internal

import co.paralleluniverse.fibers.Suspendable
import net.corda.core.crypto.*
import net.corda.core.flows.*
import net.corda.core.identity.CordaX500Name
import net.corda.core.identity.Party
import net.corda.core.internal.notary.NotaryService
import net.corda.core.transactions.SignedTransaction
import net.corda.core.utilities.getOrThrow
import net.corda.core.utilities.unwrap
import net.corda.node.services.api.ServiceHubInternal
import net.corda.testing.contracts.DummyContract
import net.corda.testing.core.ALICE_NAME
import net.corda.testing.core.singleIdentity
import net.corda.testing.node.MockNetwork
import net.corda.testing.node.MockNetworkNotarySpec
import net.corda.testing.node.MockNetworkParameters
import net.corda.testing.node.StartedMockNode
import net.corda.testing.node.internal.DUMMY_CONTRACTS_CORDAPP
import net.corda.testing.node.internal.enclosedCordapp
import org.assertj.core.api.Assertions.assertThat
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.security.PublicKey
import java.util.*
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class NotaryClientFlowRegistrationTest {
    private lateinit var mockNet: MockNetwork
    private lateinit var notaryNode: StartedMockNode
    private lateinit var aliceNode: StartedMockNode
    private lateinit var notary: Party
    private lateinit var alice: Party

    @Before
    fun setup() {
        mockNet = MockNetwork(MockNetworkParameters(
                cordappsForAllNodes = listOf(DUMMY_CONTRACTS_CORDAPP, enclosedCordapp()),
                notarySpecs = listOf(MockNetworkNotarySpec(
                        name = CordaX500Name("Custom Notary", "Amsterdam", "NL"),
                        className = "net.corda.node.internal.NotaryClientFlowRegistrationTest\$CustomClientFlowNotaryService",
                        validating = false
                ))
        ))
        aliceNode = mockNet.createPartyNode(ALICE_NAME)
        notaryNode = mockNet.defaultNotaryNode
        notary = mockNet.defaultNotaryIdentity
        alice = aliceNode.info.singleIdentity()
    }

    @After
    fun tearDown() {
        mockNet.stopNodes()
    }

    @Test
    fun `custom notary client flow is allowed`() {
        val tx = DummyContract.generateInitial(Random().nextInt(), notary, alice.ref(0))
        val stx = aliceNode.services.signInitialTransaction(tx)
        val future = aliceNode.startFlow(CustomClientFlow("VALID", stx, notary))
        mockNet.runNetwork()
        val sigs = future.getOrThrow()
        assertTrue("custom notary should sign a valid tx from a custom flow"){ sigs.any { it.by == notary.owningKey } }
    }

    @Test
    fun `custom notary client flow with invalid payload`() {
        val tx = DummyContract.generateInitial(Random().nextInt(), notary, alice.ref(0))
        val stx = aliceNode.services.signInitialTransaction(tx)
        val future = aliceNode.startFlow(CustomClientFlow("NOT VALID", stx, notary))
        mockNet.runNetwork()
        val ex = assertFailsWith<NotaryException> { future.getOrThrow() }
        val notaryError = ex.error as NotaryError.TransactionInvalid
        assertThat(notaryError.cause).hasMessageContaining("Payload should be 'VALID'")
    }

    class CustomClientFlowNotaryService(override val services: ServiceHubInternal, override val notaryIdentityKey: PublicKey) : NotaryService() {
        override fun createServiceFlow(otherPartySession: FlowSession): FlowLogic<Void?> =
                object : FlowLogic<Void?>() {
                    @Suspendable
                    override fun call(): Void? {
                        otherPartySession.receive<String>().unwrap {
                            if (it != "VALID") {
                                throw NotaryException(NotaryError.TransactionInvalid(Exception("Payload should be 'VALID'")))
                            }
                        }

                        val signableData = SignableData(SecureHash.zeroHash, SignatureMetadata(services.myInfo.platformVersion, Crypto.findSignatureScheme(notaryIdentityKey).schemeNumberID))
                        val signature = services.keyManagementService.sign(signableData, notaryIdentityKey)
                        otherPartySession.send(NotarisationResponse(listOf(signature)))
                        return null
                    }
                }

        override fun start() {}
        override fun stop() {}
    }

    class CustomClientFlow(val payload: Any, val stx: SignedTransaction, val notary: Party) : NotaryFlow.Client(stx) {
        @Suspendable
        override fun call(): List<TransactionSignature> {
            val session = initiateFlow(notary)
            session.send(payload)
            return session.receive<NotarisationResponse>().unwrap { it }.signatures
        }
    }
}
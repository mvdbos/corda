package net.corda.notary.experimental.zkp

import net.corda.core.contracts.TimeWindow
import net.corda.core.flows.NotaryException
import net.corda.core.flows.NotaryFlow
import net.corda.core.flows.ZKNotaryFlow
import net.corda.core.identity.CordaX500Name
import net.corda.core.utilities.getOrThrow
import net.corda.core.utilities.seconds
import net.corda.testing.common.internal.testNetworkParameters
import net.corda.testing.driver.DriverDSL
import net.corda.testing.driver.DriverParameters
import net.corda.testing.driver.InProcess
import net.corda.testing.driver.driver
import net.corda.testing.node.NotarySpec
import org.junit.Ignore
import org.junit.Test
import kotlin.test.assertTrue

class ZKNotaryServiceTest {
    private val notaryName = CordaX500Name("ZK Notary", "Amsterdam", "NL")
    private fun <A> network(dsl: DriverDSL.() -> A) = driver(DriverParameters(
            startNodesInProcess = true,
            extraCordappPackagesToScan = listOf("net.corda.notary.experimental.zkp"), // NotaryLoader.init does nothing for custom notaries
            notarySpecs = listOf(NotarySpec(notaryName, false)),
            notaryCustomOverrides = mapOf("notary" to mapOf(
                    "validating" to false,
                    "className" to "net.corda.notary.experimental.zkp.ZKNotaryService"
            )),
            networkParameters = testNetworkParameters(minimumPlatformVersion = 4) // required by ZKNotaryService
    ), dsl)

    @Test
    fun `confirm ZK notary signs tx within timewindow`() {
        network {
            val megaCorpNode = startNode(providedName = CordaX500Name("MegaCorp", "Amsterdam", "NL"))
                    .getOrThrow() as InProcess
            val megaCorp = megaCorpNode.nodeInfo.legalIdentities.single()
            val miniCorpNode = startNode(providedName = CordaX500Name("MiniCorp", "London", "GB"))
                    .getOrThrow() as InProcess

            val stx = miniCorpNode.startFlow(DummyIssueAndMove(
                    defaultNotaryIdentity,
                    megaCorp,
                    1234567890,
                    TimeWindow.withTolerance(miniCorpNode.services.clock.instant(), 30.seconds))
            ).getOrThrow()

            val sigs = miniCorpNode.startFlow(ZKNotaryFlow.Client(stx)).getOrThrow()
            assertTrue("tx should be signed by ZK notary") { sigs.any { it.by == defaultNotaryIdentity.owningKey } }
        }
    }

    @Test
    @Ignore
    fun `detect double spend`() {
        throw NotImplementedError()
    }
}
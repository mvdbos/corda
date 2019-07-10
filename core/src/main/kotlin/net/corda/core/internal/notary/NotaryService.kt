package net.corda.core.internal.notary

import net.corda.core.DeleteForDJVM
import net.corda.core.crypto.TransactionSignature
import net.corda.core.flows.FlowLogic
import net.corda.core.flows.FlowSession
import net.corda.core.flows.NotaryFlow
import net.corda.core.identity.Party
import net.corda.core.node.ServiceHub
import net.corda.core.serialization.SingletonSerializeAsToken
import java.security.PublicKey
import kotlin.reflect.KClass

@DeleteForDJVM
abstract class NotaryService : SingletonSerializeAsToken() {
    abstract val services: ServiceHub
    abstract val notaryIdentityKey: PublicKey

    open val initiatingFlow: KClass<out FlowLogic<*>> = NotaryFlow.Client::class

    abstract fun start()
    abstract fun stop()

    /**
     * Produces a notary service flow which has the corresponding sends and receives as [NotaryFlow.Client].
     * @param otherPartySession client [Party] making the request
     */
    abstract fun createServiceFlow(otherPartySession: FlowSession): FlowLogic<Void?>
}
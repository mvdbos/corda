package net.corda.notary.experimental.zkp

import net.corda.core.flows.FlowLogic
import net.corda.core.flows.FlowSession
import net.corda.core.flows.ZKNotaryServiceFlow
import net.corda.core.internal.notary.SinglePartyNotaryService
import net.corda.core.schemas.MappedSchema
import net.corda.core.utilities.seconds
import net.corda.node.services.api.ServiceHubInternal
import net.corda.node.services.transactions.NodeNotarySchema
import net.corda.node.services.transactions.PersistentUniquenessProvider
import java.security.PublicKey

class ZKNotaryService(override val services: ServiceHubInternal, override val notaryIdentityKey: PublicKey) : SinglePartyNotaryService() {
    override val uniquenessProvider = PersistentUniquenessProvider(services.clock, services.database, services.cacheFactory)

    init {
        if (services.networkParameters.minimumPlatformVersion < 4) {
            throw IllegalStateException("The ZKNotaryService is compatible with Corda version 4 or greater")
        }
    }

    override fun createServiceFlow(otherPartySession: FlowSession): FlowLogic<Void?> = ZKNotaryServiceFlow(
            otherPartySession,
            this,
            5.seconds // in the real world, this should come from configuration
    )

    override fun start() {}
    override fun stop() {}
}

object PersistentUniquenessProviderSchema : MappedSchema(schemaFamily = NodeNotarySchema.javaClass, version = 1,
        mappedTypes = listOf(PersistentUniquenessProvider.BaseComittedState::class.java,
                PersistentUniquenessProvider.Request::class.java,
                PersistentUniquenessProvider.CommittedState::class.java,
                PersistentUniquenessProvider.CommittedTransaction::class.java
        )) {
    override val migrationResource = "node-notary.changelog-master"
}

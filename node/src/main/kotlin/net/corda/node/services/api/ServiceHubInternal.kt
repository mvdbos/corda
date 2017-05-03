package net.corda.node.services.api

import com.google.common.annotations.VisibleForTesting
import com.google.common.util.concurrent.ListenableFuture
import net.corda.core.flows.FlowInitiator
import net.corda.core.flows.FlowLogic
import net.corda.core.flows.FlowLogicRefFactory
import net.corda.core.flows.FlowStateMachine
import net.corda.core.messaging.MessagingService
import net.corda.core.node.PluginServiceHub
import net.corda.core.node.services.TxWritableStorageService
import net.corda.core.transactions.SignedTransaction
import net.corda.core.utilities.loggerFor
import net.corda.node.internal.ServiceFlowInfo
import net.corda.node.services.statemachine.FlowStateMachineImpl

interface MessagingServiceInternal : MessagingService {
    /**
     * Initiates shutdown: if called from a thread that isn't controlled by the executor passed to the constructor
     * then this will block until all in-flight messages have finished being handled and acknowledged. If called
     * from a thread that's a part of the [net.corda.node.utilities.AffinityExecutor] given to the constructor,
     * it returns immediately and shutdown is asynchronous.
     */
    fun stop()
}

/**
 * This class lets you start up a [MessagingService]. Its purpose is to stop you from getting access to the methods
 * on the messaging service interface until you have successfully started up the system. One of these objects should
 * be the only way to obtain a reference to a [MessagingService]. Startup may be a slow process: some implementations
 * may let you cast the returned future to an object that lets you get status info.
 *
 * A specific implementation of the controller class will have extra features that let you customise it before starting
 * it up.
 */
interface MessagingServiceBuilder<out T : MessagingServiceInternal> {
    fun start(): ListenableFuture<out T>
}


abstract class ServiceHubInternal : PluginServiceHub {
    companion object {
        private val log = loggerFor<ServiceHubInternal>()
    }

    abstract val monitoringService: MonitoringService
    abstract val flowLogicRefFactory: FlowLogicRefFactory
    abstract val schemaService: SchemaService
    abstract val auditService: AuditService

    abstract override val networkService: MessagingServiceInternal

    /**
     * Given a list of [SignedTransaction]s, writes them to the given storage for validated transactions and then
     * sends them to the vault for further processing. This is intended for implementations to call from
     * [recordTransactions].
     *
     * @param txs The transactions to record.
     */
    internal fun recordTransactionsInternal(writableStorageService: TxWritableStorageService, txs: Iterable<SignedTransaction>) {
        val stateMachineRunId = FlowStateMachineImpl.currentStateMachine()?.id
        val recordedTransactions = txs.filter { writableStorageService.validatedTransactions.addTransaction(it) }
        if (stateMachineRunId != null) {
            recordedTransactions.forEach {
                storageService.stateMachineRecordedTransactionMapping.addMapping(stateMachineRunId, it.id)
            }
        } else {
            log.warn("Transactions recorded from outside of a state machine")
        }
        vaultService.notifyAll(recordedTransactions.map { it.tx })
    }

    /**
     * Starts an already constructed flow. Note that you must be on the server thread to call this method. [FlowInitiator]
     * defaults to [FlowInitiator.RPC] with username "Only For Testing".
     */
    // TODO Move it to test utils.
    @VisibleForTesting
    fun <T> startFlow(logic: FlowLogic<T>): FlowStateMachine<T> = startFlow(logic, FlowInitiator.RPC("Only For Testing"))

    /**
     * Starts an already constructed flow. Note that you must be on the server thread to call this method.
     * @param flowInitiator indicates who started the flow, see: [FlowInitiator].
     */
    abstract fun <T> startFlow(logic: FlowLogic<T>, flowInitiator: FlowInitiator): FlowStateMachine<T>


    /**
     * Will check [logicType] and [args] against a whitelist and if acceptable then construct and initiate the flow.
     * Note that you must be on the server thread to call this method. [flowInitiator] points how flow was started,
     * See: [FlowInitiator].
     *
     * @throws net.corda.core.flows.IllegalFlowLogicException or IllegalArgumentException if there are problems with the
     * [logicType] or [args].
     */
    fun <T : Any> invokeFlowAsync(
            logicType: Class<out FlowLogic<T>>,
            flowInitiator: FlowInitiator,
            vararg args: Any?): FlowStateMachine<T> {
        val logicRef = flowLogicRefFactory.create(logicType, *args)
        @Suppress("UNCHECKED_CAST")
        val logic = flowLogicRefFactory.toFlowLogic(logicRef) as FlowLogic<T>
        return startFlow(logic, flowInitiator)
    }

    abstract fun getServiceFlowFactory(clientFlowClass: Class<out FlowLogic<*>>): ServiceFlowInfo?
}
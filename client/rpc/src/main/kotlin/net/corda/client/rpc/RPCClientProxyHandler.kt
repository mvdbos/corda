package net.corda.client.rpc

import com.esotericsoftware.kryo.Kryo
import com.esotericsoftware.kryo.Serializer
import com.esotericsoftware.kryo.io.Input
import com.esotericsoftware.kryo.io.Output
import com.esotericsoftware.kryo.pool.KryoPool
import com.google.common.cache.Cache
import com.google.common.cache.CacheBuilder
import com.google.common.cache.RemovalCause
import com.google.common.cache.RemovalListener
import com.google.common.util.concurrent.SettableFuture
import com.google.common.util.concurrent.ThreadFactoryBuilder
import net.corda.core.ThreadBox
import net.corda.core.getOrThrow
import net.corda.core.messaging.RPCOps
import net.corda.core.pinInSubscriptions
import net.corda.core.random63BitValue
import net.corda.core.serialization.KryoPoolWithContext
import net.corda.core.utilities.*
import net.corda.nodeapi.*
import org.apache.activemq.artemis.api.core.SimpleString
import org.apache.activemq.artemis.api.core.client.ActiveMQClient.DEFAULT_ACK_BATCH_SIZE
import org.apache.activemq.artemis.api.core.client.ClientMessage
import org.apache.activemq.artemis.api.core.client.ServerLocator
import rx.Notification
import rx.Observable
import rx.subjects.UnicastSubject
import java.lang.reflect.InvocationHandler
import java.lang.reflect.Method
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import kotlin.collections.ArrayList
import kotlin.reflect.jvm.javaGetter

/**
 * This class provides a proxy implementation of an RPC interface for RPC clients. It translates API calls to lower-level
 * RPC protocol messages. For this protocol see [RPCApi].
 *
 * When a method is called on the interface the arguments are serialised and the request is forwarded to the node. The
 * server then executes the code that implements the RPC and sends a reply.
 *
 * An RPC reply may contain [Observable]s, which are serialised simply as unique IDs. On the client side we create a
 * [UnicastSubject] for each such ID. Subsequently the server may send observations attached to this ID, which are
 * forwarded to the [UnicastSubject]. Note that the observations themselves may contain further [Observable]s, which are
 * handled in the same way.
 *
 * To do the above we take advantage of Kryo's datastructure traversal. When the client is deserialising a message from
 * the server that may contain Observables it is supplied with an [ObservableContext] that exposes the map used to demux
 * the observations. When an [Observable] is encountered during traversal a new [UnicastSubject] is added to the map and
 * we carry on. Each observation later contains the corresponding Observable ID, and we just forward that to the
 * associated [UnicastSubject].
 *
 * The client may signal that it no longer consumes a particular [Observable]. This may be done explicitly by
 * unsubscribing from the [Observable], or if the [Observable] is garbage collected the client will eventually
 * automatically signal the server. This is done using a cache that holds weak references to the [UnicastSubject]s.
 * The cleanup happens in batches using a dedicated reaper, scheduled on [reaperExecutor].
 */
internal class RPCClientProxyHandler(
        private val rpcConfiguration: RPCClientConfiguration,
        private val rpcUsername: String,
        private val rpcPassword: String,
        private val serverLocator: ServerLocator,
        private val clientAddress: SimpleString
) : InvocationHandler {

    private enum class State {
        UNSTARTED,
        SERVER_VERSION_NOT_SET,
        STARTED,
        FINISHED
    }
    private val lifeCycle = LifeCycle(State.UNSTARTED)

    private companion object {
        val log = loggerFor<RPCClientProxyHandler>()
        // Note that this KryoPool is not yet capable of deserialising Observables, it requires Proxy-specific context
        // to do that. However it may still be used for serialisation of RPC requests and related messages.
        val kryoPool = KryoPool.Builder { RPCKryo(RpcClientObservableSerializer) }.build()
    }

    // Used for reaping
    private val reaperExecutor = Executors.newScheduledThreadPool(
            1,
            ThreadFactoryBuilder().setNameFormat("rpc-client-reaper-%d").build()
    )

    // A sticky pool for running Observable.onNext()s. We need the stickiness to preserve the observation ordering.
    private val observationExecutorThreadFactory = ThreadFactoryBuilder().setNameFormat("rpc-client-observation-pool-%d").build()
    private val observationExecutorPool = LazyStickyPool(rpcConfiguration.observationExecutorPoolSize) {
        Executors.newFixedThreadPool(1, observationExecutorThreadFactory)
    }

    // Holds the RPC reply futures.
    private val rpcReplyMap = ConcurrentHashMap<RPCApi.RpcRequestId, SettableFuture<Any?>>()
    // Holds the Observables and a reference store to keep Observables alive when subscribed to.
    private val observableContext = ObservableContext(
            observableMap = createRpcObservableMap(),
            hardReferenceStore = Collections.synchronizedSet(mutableSetOf<Observable<*>>())
    )
    // Holds a reference to the scheduled reaper.
    private lateinit var reaperScheduledFuture: ScheduledFuture<*>
    // The protocol version of the server, to be initialised to the value of [RPCOps.protocolVersion]
    private var serverProtocolVersion: Int? = null

    // Stores the Observable IDs that are already removed from the map but are not yet sent to the server.
    private val observablesToReap = ThreadBox(object {
        var observables = ArrayList<RPCApi.ObservableId>()
    })
    // A Kryo pool that automatically adds the observable context when an instance is requested.
    private val kryoPoolWithObservableContext = RpcClientObservableSerializer.createPoolWithContext(kryoPool, observableContext)

    private fun createRpcObservableMap(): RpcObservableMap {
        val onObservableRemove = RemovalListener<RPCApi.ObservableId, UnicastSubject<Notification<Any>>> {
            if (it.cause == RemovalCause.COLLECTED) {
                log.warn("Observable was never subscribed to, scheduling for reaping")
            }
            observablesToReap.locked { observables.add(it.key) }
        }
        return CacheBuilder.newBuilder().
                weakValues().
                removalListener(onObservableRemove).
                concurrencyLevel(rpcConfiguration.cacheConcurrencyLevel).
                build()
    }

    // We cannot pool consumers as we need to preserve the original muxed message order.
    // TODO We may need to pool these somehow anyway, otherwise if the server sends many big messages in parallel a
    // single consumer may be starved for flow control credits. Recheck this once Artemis's large message streaming is
    // integrated properly.
    private lateinit var sessionAndConsumer: ArtemisConsumer
    // Pool producers to reduce contention on the client side.
    private val sessionAndProducerPool = LazyPool(bound = rpcConfiguration.producerPoolBound) {
        // Note how we create new sessions *and* session factories per producer.
        // We cannot simply pool producers on one session because sessions are single threaded.
        // We cannot simply pool sessions on one session factory because flow control credits are tied to factories, so
        // sessions tend to starve each other when used concurrently.
        val sessionFactory = serverLocator.createSessionFactory()
        val session = sessionFactory.createSession(rpcUsername, rpcPassword, false, true, true, false, DEFAULT_ACK_BATCH_SIZE)
        session.start()
        ArtemisProducer(sessionFactory, session, session.createProducer(RPCApi.RPC_SERVER_QUEUE_NAME))
    }

    /**
     * Start the client. This creates the per-client queue, starts the consumer session and the reaper.
     */
    fun start() {
        lifeCycle.transition(State.UNSTARTED, State.SERVER_VERSION_NOT_SET)
        reaperScheduledFuture = reaperExecutor.scheduleAtFixedRate(
                this::reapObservables,
                rpcConfiguration.reapIntervalMs,
                rpcConfiguration.reapIntervalMs,
                TimeUnit.MILLISECONDS
        )
        sessionAndProducerPool.run {
            it.session.createTemporaryQueue(clientAddress, clientAddress)
        }
        val sessionFactory = serverLocator.createSessionFactory()
        val session = sessionFactory.createSession(rpcUsername, rpcPassword, false, true, true, false, DEFAULT_ACK_BATCH_SIZE)
        val consumer = session.createConsumer(clientAddress)
        consumer.setMessageHandler(this@RPCClientProxyHandler::artemisMessageHandler)
        session.start()
        sessionAndConsumer = ArtemisConsumer(sessionFactory, session, consumer)
    }

    // This is the general function that transforms a client side RPC to internal Artemis messages.
    override fun invoke(proxy: Any, method: Method, arguments: Array<out Any?>?): Any? {
        checkProtocolVersion(method)
        val rpcId = RPCApi.RpcRequestId(random63BitValue())
        val request = RPCApi.ClientToServer.RpcRequest(clientAddress, rpcId, method.name, arguments?.toList() ?: emptyList())
        val replyFuture = SettableFuture.create<Any>()
        sessionAndProducerPool.run {
            val message = it.session.createMessage(false)
            request.writeToClientMessage(kryoPool, message)
            log.debug { "Sending RPC request ${method.name} with id $rpcId" }
            require(rpcReplyMap.put(rpcId, replyFuture) == null) {
                "Generated several RPC requests with same ID $rpcId"
            }
            it.producer.send(message)
        }
        return replyFuture.getOrThrow()
    }

    // The handler for Artemis messages.
    private fun artemisMessageHandler(message: ClientMessage) {
        message.acknowledge()
        val serverToClient = RPCApi.ServerToClient.fromClientMessage(kryoPoolWithObservableContext, message)
        log.debug { "Got message from RPC server $serverToClient" }
        serverToClient.accept(
                onRpcReply = {
                    val replyFuture = rpcReplyMap.remove(it.id)
                    if (replyFuture == null) {
                        log.error("RPC reply arrived to unknown RPC ID ${it.id}, this indicates an internal RPC error.")
                        return@accept
                    }
                    it.result.match(
                            onError = { replyFuture.setException(it) },
                            onValue = { replyFuture.set(it) }
                    )
                },
                onObservation = {
                    val observable = observableContext.observableMap.getIfPresent(it.id)
                    if (observable == null) {
                        log.warn("Observation ${it.content} arrived to unknown Observable with ID ${it.id}. " +
                                "This may be due to an observation arriving before the server was " +
                                "notified of observable shutdown")
                        return@accept
                    }
                    // We schedule the onNext() on an executor sticky-pooled based on the Observable ID.
                    observationExecutorPool.run(it.id) { executor ->
                        executor.submit {
                            observable.onNext(it.content)
                            if (it.content.isOnCompleted || it.content.isOnError) {
                                observableContext.observableMap.invalidate(it.id)
                            }
                        }
                    }
                }
        )
    }

    /**
     * Closes the RPC proxy. Reaps all observables, shuts down the reaper, closes all sessions and executors.
     */
    fun close() {
        lifeCycle.transition(State.STARTED, State.FINISHED)
        reaperScheduledFuture.cancel(false)
        observableContext.observableMap.invalidateAll()
        reapObservables()
        reaperExecutor.shutdownNow()
        sessionAndProducerPool.close().forEach {
            it.producer.close()
            it.session.close()
            it.sessionFactory.close()
        }
        sessionAndConsumer.consumer.close()
        sessionAndConsumer.session.close()
        sessionAndConsumer.sessionFactory.close()
        // Note the ordering is important, we shut down the consumer *before* the observation executor, otherwise we may
        // leak borrowed executors.
        val observationExecutors = observationExecutorPool.close()
        observationExecutors.forEach { it.shutdownNow() }
        observationExecutors.forEach { it.awaitTermination(100, TimeUnit.MILLISECONDS) }
    }

    /**
     * Check the [RPCSinceVersion] of the passed in [calledMethod] against the server's protocol version.
     */
    private fun checkProtocolVersion(calledMethod: Method) {
        val serverProtocolVersion = serverProtocolVersion
        if (serverProtocolVersion == null) {
            lifeCycle.requireState(State.SERVER_VERSION_NOT_SET)
        } else {
            lifeCycle.requireState(State.STARTED)
            val sinceVersion = calledMethod.getAnnotation(RPCSinceVersion::class.java)?.version ?: 0
            if (sinceVersion > serverProtocolVersion) {
                throw UnsupportedOperationException("Method $calledMethod was added in RPC protocol version $sinceVersion but the server is running $serverProtocolVersion")
            }
        }
    }

    /**
     * Set the server's protocol version. Note that before doing so the client is not considered fully started, although
     * RPCs already may be called with it.
     */
    internal fun setServerProtocolVersion(version: Int) {
        lifeCycle.transition(State.SERVER_VERSION_NOT_SET, State.STARTED)
        if (serverProtocolVersion == null) {
            serverProtocolVersion = version
        } else {
            throw IllegalStateException("setServerProtocolVersion called, but the protocol version was already set!")
        }
    }

    private fun reapObservables() {
        observableContext.observableMap.cleanUp()
        val observableIds = observablesToReap.locked {
            if (observables.isNotEmpty()) {
                val temporary = observables
                observables = ArrayList()
                temporary
            } else {
                null
            }
        }
        if (observableIds != null) {
            log.debug { "Reaping ${observableIds.size} observables" }
            sessionAndProducerPool.run {
                val message = it.session.createMessage(false)
                RPCApi.ClientToServer.ObservablesClosed(observableIds).writeToClientMessage(message)
                it.producer.send(message)
            }
        }
    }
}

private typealias RpcObservableMap = Cache<RPCApi.ObservableId, UnicastSubject<Notification<Any>>>

/**
 * Holds a context available during Kryo deserialisation of messages that are expected to contain Observables.
 *
 * @param observableMap holds the Observables that are ultimately exposed to the user.
 * @param hardReferenceStore holds references to Observables we want to keep alive while they are subscribed to.
 */
private data class ObservableContext(
        val observableMap: RpcObservableMap,
        val hardReferenceStore: MutableSet<Observable<*>>
)

/**
 * A [Serializer] to deserialise Observables once the corresponding Kryo instance has been provided with an [ObservableContext].
 */
private object RpcClientObservableSerializer : Serializer<Observable<Any>>() {
    private object RpcObservableContextKey
    fun createPoolWithContext(kryoPool: KryoPool, observableContext: ObservableContext): KryoPool {
        return KryoPoolWithContext(kryoPool, RpcObservableContextKey, observableContext)
    }

    override fun read(kryo: Kryo, input: Input, type: Class<Observable<Any>>): Observable<Any> {
        @Suppress("UNCHECKED_CAST")
        val observableContext = kryo.context[RpcObservableContextKey] as ObservableContext
        val observableId = RPCApi.ObservableId(input.readLong(true))
        val observable = UnicastSubject.create<Notification<Any>>()
        require(observableContext.observableMap.getIfPresent(observableId) == null) {
            "Multiple Observables arrived with the same ID $observableId"
        }
        observableContext.observableMap.put(observableId, observable)
        // We pin all Observables into a hard reference store (rooted in the RPC proxy) on subscription so that users
        // don't need to store a reference to the Observables themselves.
        // TODO Is this correct behaviour? It may result in unintended leaks in app code.
        return observable.pinInSubscriptions(observableContext.hardReferenceStore).doOnUnsubscribe {
            // This causes Future completions to give warnings because the corresponding OnComplete sent from the server
            // will arrive after the client unsubscribes from the observable and consequently invalidates the mapping.
            // The unsubscribe is due to [ObservableToFuture]'s use of first().
            observableContext.observableMap.invalidate(observableId)
        }.dematerialize()
    }

    override fun write(kryo: Kryo, output: Output, observable: Observable<Any>) {
        throw UnsupportedOperationException("Cannot serialise Observables on the client side")
    }
}
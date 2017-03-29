package net.corda.client.rpc

import com.google.common.net.HostAndPort
import net.corda.core.*
import net.corda.core.messaging.CordaRPCOps
import net.corda.core.messaging.RPCOps
import net.corda.core.utilities.loggerFor
import net.corda.nodeapi.ArtemisTcpTransport.Companion.tcpTransport
import net.corda.nodeapi.ConnectionDirection
import net.corda.nodeapi.RPCException
import net.corda.nodeapi.RPCApi
import net.corda.nodeapi.config.SSLConfiguration
import org.apache.activemq.artemis.api.core.SimpleString
import org.apache.activemq.artemis.api.core.TransportConfiguration
import org.apache.activemq.artemis.api.core.client.ActiveMQClient
import java.io.Closeable
import java.lang.reflect.Proxy

typealias CordaRPCClient = RPCClient<CordaRPCOps>
typealias CordaRPCConnection = RPCClient.RPCConnection<CordaRPCOps>
fun CordaRPCClient.start(
        username: String,
        password: String
) = start(CordaRPCOps::class.java, username, password)

data class RPCClientConfiguration(
        /** The minimum protocol version required from the server */
        val minimumServerProtocolVersion: Int,
        /** The interval of unused observable reaping in milliseconds */
        val reapIntervalMs: Long,
        /** The number of threads to use for observations (for executing [Observable.onNext]) */
        val observationExecutorPoolSize: Int,
        /** The maximum number of producers to create to handle outgoing messages */
        val producerPoolBound: Int,
        /**
         * Determines the concurrency level of the Observable Cache. This is exposed because it implicitly determines
         * the limit on the number of leaked observables reaped because of garbage collection per reaping.
         * See the implementation of [com.google.common.cache.LocalCache] for details.
         */
        val cacheConcurrencyLevel: Int,
        /** The retry interval of artemis connections in milliseconds */
        val connectionRetryIntervalMs: Long,
        /** The retry interval multiplier for exponential backoff */
        val connectionRetryIntervalMultiplier: Double,
        /** Maximum retry interval */
        val connectionMaxRetryIntervalMs: Long,
        /** Maximum file size */
        val maxFileSize: Int
) {
    companion object {
        val default = RPCClientConfiguration(
                minimumServerProtocolVersion = 0,
                reapIntervalMs = 1000,
                observationExecutorPoolSize = 4,
                producerPoolBound = 1,
                cacheConcurrencyLevel = 8,
                connectionRetryIntervalMs = 5.seconds.toMillis(),
                connectionRetryIntervalMultiplier = 1.5,
                connectionMaxRetryIntervalMs = 3.minutes.toMillis(),
                /** 10 MiB maximum allowed file size for attachments, including message headers. TODO: acquire this value from Network Map when supported. */
                maxFileSize = 10485760
        )
    }
}

/**
 * An RPC client that may be used to create connections to an RPC server.
 *
 * @param transport The Artemis transport to use to connect to the server.
 * @param rpcConfiguration Configuration used to tweak client behaviour.
 */
class RPCClient<I : RPCOps>(
        val transport: TransportConfiguration,
        val rpcConfiguration: RPCClientConfiguration = RPCClientConfiguration.default
) {
    constructor(
            hostAndPort: HostAndPort,
            sslConfiguration: SSLConfiguration? = null,
            rpcConfiguration: RPCClientConfiguration = RPCClientConfiguration.default
    ) : this(tcpTransport(ConnectionDirection.Outbound(), hostAndPort, sslConfiguration), rpcConfiguration)

    companion object {
        private val log = loggerFor<RPCClient<*>>()
    }

    interface RPCConnection<out I : RPCOps> : Closeable {
        val proxy: I
        val serverProtocolVersion: Int
    }

    /**
     * Returns an [RPCConnection] containing a proxy that lets you invoke RPCs on the server. Calls on it block, and if
     * the server throws an exception then it will be rethrown on the client. Proxies are thread safe and may be used to
     * invoke multiple RPCs in parallel.
     **
     * RPC sends and receives are logged on the net.corda.rpc logger.
     *
     * The [RPCOps] defines what client RPCs are available. If an RPC returns an [Observable] anywhere in the object
     * graph returned then the server-side observable is transparently forwarded to the client side here.
     * *You are expected to use it*. The server will begin buffering messages immediately that it will expect you to
     * drain by subscribing to the returned observer. You can opt-out of this by simply calling the
     * [net.corda.client.rpc.notUsed] method on it. You don't have to explicitly close the observable if you actually
     * subscribe to it: it will close itself and free up the server-side resources either when the client or JVM itself
     * is shutdown, or when there are no more subscribers to it. Once all the subscribers to a returned observable are
     * unsubscribed, the observable is closed and you can't then re-subscribe again: you'll have to re-request a fresh
     * observable with another RPC.
     *
     * @param rpcOpsClass The [Class] of the RPC interface.
     * @param username The username to authenticate with.
     * @param password The password to authenticate with.
     * @throws RPCException if the server version is too low or if the server isn't reachable within the given time.
     */
    fun start(
            rpcOpsClass: Class<I>,
            username: String,
            password: String
    ): RPCConnection<I> {
        return log.logElapsedTime("Startup") {
            val clientAddress = SimpleString("${RPCApi.RPC_CLIENT_QUEUE_NAME_PREFIX}.$username.${random63BitValue()}")

            val serverLocator = ActiveMQClient.createServerLocatorWithoutHA(transport).apply {
                retryInterval = rpcConfiguration.connectionRetryIntervalMs
                retryIntervalMultiplier = rpcConfiguration.connectionRetryIntervalMultiplier
                maxRetryInterval = rpcConfiguration.connectionMaxRetryIntervalMs
                minLargeMessageSize = rpcConfiguration.maxFileSize
            }

            val proxyHandler = RPCClientProxyHandler(rpcConfiguration, username, password, serverLocator, clientAddress)
            proxyHandler.start()

            @Suppress("UNCHECKED_CAST")
            val ops = Proxy.newProxyInstance(rpcOpsClass.classLoader, arrayOf(rpcOpsClass), proxyHandler) as I

            val serverProtocolVersion = ops.protocolVersion
            if (serverProtocolVersion < rpcConfiguration.minimumServerProtocolVersion) {
                throw RPCException("Requested minimum protocol version (${rpcConfiguration.minimumServerProtocolVersion}) is higher" +
                        " than the server's supported protocol version ($serverProtocolVersion)")
            }
            proxyHandler.setServerProtocolVersion(serverProtocolVersion)

            log.debug("RPC connected, returning proxy")
            object : RPCConnection<I> {
                override val proxy = ops
                override val serverProtocolVersion = serverProtocolVersion
                override fun close() {
                    proxyHandler.close()
                    serverLocator.close()
                }
            }
        }
    }
}

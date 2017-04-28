package net.corda.client.rpc

import com.google.common.util.concurrent.Futures
import com.google.common.util.concurrent.ListenableFuture
import net.corda.core.future
import net.corda.core.messaging.RPCOps
import net.corda.node.services.messaging.RPCServerConfiguration
import net.corda.nodeapi.RPCApi
import net.corda.testing.rpcDriver
import net.corda.testing.startRandomRpcClient
import net.corda.testing.startRpcClient
import org.apache.activemq.artemis.api.core.SimpleString
import org.junit.Test
import rx.Observable
import rx.subjects.PublishSubject
import rx.subjects.UnicastSubject
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger


class RPCCleanupTests {

    interface LeakObservableOps: RPCOps {
        fun leakObservable(): Observable<Nothing>
    }

    @Test
    fun `client cleans up leaked observables`() {
        rpcDriver {
            val leakObservableOpsImpl = object : LeakObservableOps {
                val leakedUnsubscribedCount = AtomicInteger(0)
                override val protocolVersion = 0
                override fun leakObservable(): Observable<Nothing> {
                    return PublishSubject.create<Nothing>().doOnUnsubscribe {
                        leakedUnsubscribedCount.incrementAndGet()
                    }
                }
            }
            val server = startRpcServer<LeakObservableOps>(ops = leakObservableOpsImpl)
            val proxy = startRpcClient<LeakObservableOps>(server.get().hostAndPort).get()
            // Leak many observables
            val N = 200
            (1..N).toList().parallelStream().forEach {
                proxy.leakObservable()
            }
            // In a loop force GC and check whether the server is notified
            while (true) {
                System.gc()
                if (leakObservableOpsImpl.leakedUnsubscribedCount.get() == N) break
                Thread.sleep(100)
            }
        }
    }

    interface TrackSubscriberOps : RPCOps {
        fun subscribe(): Observable<Unit>
    }

    /**
     * In this test we create a number of out of process RPC clients that call [TrackSubscriberOps.subscribe] in a loop.
     */
    @Test
    fun `server cleans up queues after disconnected clients`() {
        rpcDriver {
            val trackSubscriberOpsImpl = object : TrackSubscriberOps {
                override val protocolVersion = 0
                val subscriberCount = AtomicInteger(0)
                val trackSubscriberCountObservable = UnicastSubject.create<Unit>().share().
                        doOnSubscribe { subscriberCount.incrementAndGet() }.
                        doOnUnsubscribe { subscriberCount.decrementAndGet() }
                override fun subscribe(): Observable<Unit> {
                    return trackSubscriberCountObservable
                }
            }
            val server = startRpcServer<TrackSubscriberOps>(
                    configuration = RPCServerConfiguration.default.copy(
                            reapIntervalMs = 100
                    ),
                    ops = trackSubscriberOpsImpl
            ).get()

            val numberOfClients = 4
            val clients = Futures.allAsList((1 .. numberOfClients).map {
                startRandomRpcClient<TrackSubscriberOps>(server.hostAndPort)
            }).get()

            // Start a session to poll the overall number of RPC clients
            val session = startArtemisSession(server.hostAndPort)
            fun pollUntilClientNumber(expected: Int) {
                pollUntilTrue("number of RPC clients to become $expected") {
                    val queryResult = session.addressQuery(SimpleString("${RPCApi.RPC_CLIENT_QUEUE_NAME_PREFIX}.#"))
                    queryResult.queueNames.size == expected
                }.get()
            }

            // Poll until all clients connect
            pollUntilClientNumber(numberOfClients)
            pollUntilTrue("number of times subscribe() has been called") { trackSubscriberOpsImpl.subscriberCount.get() >= 100 }.get()
            // Kill one client
            clients[0].destroyForcibly()
            pollUntilClientNumber(numberOfClients - 1)
            // Kill the rest
            (1 .. numberOfClients - 1).forEach {
                clients[it].destroyForcibly()
            }
            pollUntilClientNumber(0)
            // Now poll until the server detects the disconnects and unsubscribes from all obserables.
            pollUntilTrue("number of times subscribe() has been called") { trackSubscriberOpsImpl.subscriberCount.get() == 0 }.get()
        }
    }
}
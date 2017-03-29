package net.corda.client.rpc

import com.google.common.util.concurrent.Futures
import com.google.common.util.concurrent.ListenableFuture
import net.corda.core.future
import net.corda.core.messaging.RPCOps
import net.corda.core.random63BitValue
import net.corda.core.serialization.CordaSerializable
import net.corda.node.driver.poll
import net.corda.node.services.messaging.RPCServerConfiguration
import net.corda.nodeapi.RPCApi
import net.corda.testing.RPCDriverExposedDSLInterface
import net.corda.testing.rpcDriver
import net.corda.testing.startRandomRpcClient
import org.apache.activemq.artemis.api.core.SimpleString
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import rx.Observable
import rx.subjects.PublishSubject
import rx.subjects.UnicastSubject
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

@RunWith(Parameterized::class)
class RPCConcurrencyTests : AbstractRPCTest() {

    @CordaSerializable
    data class ObservableRose<out A>(val value: A, val branches: Observable<out ObservableRose<A>>)

    private interface TestOps : RPCOps {
        fun newLatch(numberOfDowns: Int): Long
        fun waitLatch(id: Long)
        fun downLatch(id: Long)
        fun getImmediateObservableTree(depth: Int, branchingFactor: Int): ObservableRose<Int>
        fun leakObservable(): Observable<Nothing>
        fun getParallelObservableTree(depth: Int, branchingFactor: Int): ObservableRose<Int>
    }

    class TestOpsImpl : TestOps {
        private val latches = ConcurrentHashMap<Long, CountDownLatch>()
        val leakedUnsubscribedCount = AtomicInteger(0)
        override val protocolVersion = 0

        override fun newLatch(numberOfDowns: Int): Long {
            val id = random63BitValue()
            val latch = CountDownLatch(numberOfDowns)
            latches.put(id, latch)
            return id
        }

        override fun waitLatch(id: Long) {
            latches[id]!!.await()
        }

        override fun downLatch(id: Long) {
            latches[id]!!.countDown()
        }

        override fun getImmediateObservableTree(depth: Int, branchingFactor: Int): ObservableRose<Int> {
            val branches = if (depth == 0) {
                Observable.empty<ObservableRose<Int>>()
            } else {
                Observable.just(getImmediateObservableTree(depth - 1, branchingFactor)).repeat(branchingFactor.toLong())
            }
            return ObservableRose(depth, branches)
        }

        override fun getParallelObservableTree(depth: Int, branchingFactor: Int): ObservableRose<Int> {
            val branches = if (depth == 0) {
                Observable.empty<ObservableRose<Int>>()
            } else {
                val publish = UnicastSubject.create<ObservableRose<Int>>()
                future {
                    (1 .. branchingFactor).toList().parallelStream().forEach {
                        publish.onNext(getParallelObservableTree(depth - 1, branchingFactor))
                    }
                    publish.onCompleted()
                }
                publish
            }
            return ObservableRose(depth, branches)
        }

        override fun leakObservable(): Observable<Nothing> {
            return PublishSubject.create<Nothing>().doOnUnsubscribe {
                leakedUnsubscribedCount.incrementAndGet()
            }
        }
    }

    private lateinit var testOpsImpl: TestOpsImpl
    private fun RPCDriverExposedDSLInterface.testProxy(): TestProxy<TestOps> {
        testOpsImpl = TestOpsImpl()
        return testProxy<TestOps>(
                testOpsImpl,
                clientConfiguration = RPCClientConfiguration.default.copy(
                        reapIntervalMs = 100,
                        cacheConcurrencyLevel = 16
                ),
                serverConfiguration = RPCServerConfiguration.default.copy(
                        rpcThreadPoolSize = 4
                )
        )
    }

    @Test
    fun `call multiple RPCs in parallel`() {
        rpcDriver {
            val proxy = testProxy()
            val numberOfBlockedCalls = 2
            val numberOfDownsRequired = 100
            val id = proxy.ops.newLatch(numberOfDownsRequired)
            val done = CountDownLatch(numberOfBlockedCalls)
            // Start a couple of blocking RPC calls
            (1 .. numberOfBlockedCalls).forEach {
                future {
                    proxy.ops.waitLatch(id)
                    done.countDown()
                }
            }
            // Down the latch that the other's are waiting for concurrently
            (1 .. numberOfDownsRequired).toList().parallelStream().forEach {
                proxy.ops.downLatch(id)
            }
            done.await()
        }
    }

    private fun intPower(base: Int, power: Int): Int {
        return when (power) {
            0 -> 1
            1 -> base
            else -> {
                val a = intPower(base, power / 2)
                if (power and 1 == 0) {
                    a * a
                } else {
                    a * a * base
                }
            }
        }
    }

    @Test
    fun `nested immediate observables sequence correctly`() {
        rpcDriver {
            val proxy = testProxy()
            val treeDepth = 6
            val treeBranchingFactor = 3
            val remainingLatch = CountDownLatch((intPower(treeBranchingFactor, treeDepth + 1) - 1) / (treeBranchingFactor - 1))

            val depthsSeen = Collections.synchronizedSet(HashSet<Int>())
            fun ObservableRose<Int>.subscribeToAll() {
                remainingLatch.countDown()
                this.branches.subscribe { tree ->
                    (tree.value + 1 .. treeDepth - 1).forEach {
                        require(it in depthsSeen) { "Got ${tree.value} before $it" }
                    }
                    depthsSeen.add(tree.value)
                    tree.subscribeToAll()
                }
            }
            proxy.ops.getImmediateObservableTree(treeDepth, treeBranchingFactor).subscribeToAll()
            remainingLatch.await()
        }
    }

    @Test
    fun `parallel nested observables`() {
        rpcDriver {
            val proxy = testProxy()
            val treeDepth = 2
            val treeBranchingFactor = 10
            val remainingLatch = CountDownLatch((intPower(treeBranchingFactor, treeDepth + 1) - 1) / (treeBranchingFactor - 1))
            fun ObservableRose<Int>.subscribeToAll() {
                remainingLatch.countDown()
                branches.subscribe(ObservableRose<Int>::subscribeToAll)
            }
            proxy.ops.getParallelObservableTree(treeDepth, treeBranchingFactor).subscribeToAll()
            remainingLatch.await()
        }
    }

    @Test
    fun `client cleans up leaked observables`() {
        rpcDriver {
            val proxy = testProxy()
            val N = 200
            (1 .. N).toList().parallelStream().forEach {
                proxy.ops.leakObservable()
            }
            while (true) {
                System.gc()
                if (testOpsImpl.leakedUnsubscribedCount.get() == N) break
                Thread.sleep(100)
            }
        }
    }

    interface SmallRPCOps : RPCOps {
        fun someFunction(string: String): Observable<String>
        fun someOtherFunction(int: Int?): ListenableFuture<Int?>
    }

    @Ignore("TODO This test needs more thought, it's too flaky now. We need some way of signalling that the " +
            "out-of-process RPC clients have indeed started to emit events (there is a long delay between creating of " +
            "the artemis queues and the first RPC going through because of kryo slowness)")
    @Test
    fun `server cleans up queues after disconnected clients`() {
        rpcDriver {
            val server = startRpcServer<SmallRPCOps>(
                    configuration = RPCServerConfiguration.default.copy(
                            reapIntervalMs = 100
                    ),
                    connectionTtlMs = 1000,
                    ops = object : SmallRPCOps {
                        override val protocolVersion = 0
                        override fun someFunction(string: String): Observable<String> {
                            return Observable.interval(1, TimeUnit.SECONDS).map { string }
                        }

                        override fun someOtherFunction(int: Int?): ListenableFuture<Int?> {
                            return future {
                                Thread.sleep(1000)
                                int
                            }
                        }
                    }).get()

            val numberOfClients = 4
            val clients = Futures.allAsList((1 .. numberOfClients).map {
                startRandomRpcClient<SmallRPCOps>(server.hostAndPort)
            }).get()

            val session = startArtemisSession(server.hostAndPort)
            val executor = Executors.newScheduledThreadPool(1)

            fun pollUntilClientNumber(expected: Int) {
                val pollResult = poll(executor, "number of RPC clients to become $expected") {
                    val queryResult = session.addressQuery(SimpleString("${RPCApi.RPC_CLIENT_QUEUE_NAME_PREFIX}.#"))
                    println(queryResult.queueNames)
                    if (queryResult.queueNames.size == expected) {
                        Unit
                    } else {
                        null
                    }
                }
                shutdownManager.registerShutdown {
                    pollResult.cancel(true)
                }
                pollResult.get()
            }
            pollUntilClientNumber(numberOfClients)
            Thread.sleep(3000)
            clients[0].destroyForcibly()
            pollUntilClientNumber(numberOfClients - 1)
            (1 .. numberOfClients - 1).forEach {
                clients[it].destroyForcibly()
            }
            pollUntilClientNumber(0)
        }
    }
}
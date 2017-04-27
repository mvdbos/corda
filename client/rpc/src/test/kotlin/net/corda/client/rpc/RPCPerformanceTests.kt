package net.corda.client.rpc

import com.codahale.metrics.Gauge
import com.codahale.metrics.JmxReporter
import com.codahale.metrics.MetricRegistry
import com.google.common.base.Stopwatch
import net.corda.client.rpc.internal.RPCClientConfiguration
import net.corda.core.messaging.RPCOps
import net.corda.node.driver.DriverDSL
import net.corda.node.driver.DriverDSLExposedInterface
import net.corda.node.driver.ShutdownManager
import net.corda.node.services.messaging.RPCServerConfiguration
import net.corda.testing.RPCDriverExposedDSLInterface
import net.corda.testing.rpcDriver
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import java.util.*
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock
import javax.management.ObjectName
import kotlin.concurrent.thread
import kotlin.concurrent.withLock

@RunWith(Parameterized::class)
class RPCPerformanceTests : AbstractRPCTest() {
    companion object {
        @JvmStatic @Parameterized.Parameters(name = "Mode = {0}")
        fun modes() = modes(RPCTestMode.Netty)
    }
    private interface TestOps : RPCOps {
        fun simpleReply(input: ByteArray, sizeOfReply: Int): ByteArray
    }

    class TestOpsImpl : TestOps {
        override val protocolVersion = 0
        override fun simpleReply(input: ByteArray, sizeOfReply: Int): ByteArray {
            return ByteArray(sizeOfReply)
        }
    }

    private fun RPCDriverExposedDSLInterface.testProxy(
            clientConfiguration: RPCClientConfiguration,
            serverConfiguration: RPCServerConfiguration
    ): TestProxy<TestOps> {
        return testProxy<TestOps>(
                TestOpsImpl(),
                clientConfiguration = clientConfiguration,
                serverConfiguration = serverConfiguration
        )
    }

    private fun warmup() {
        rpcDriver {
            val proxy = testProxy(
                    RPCClientConfiguration.default,
                    RPCServerConfiguration.default
            )
            val executor = Executors.newFixedThreadPool(4)
            val N = 10000
            val latch = CountDownLatch(N)
            for (i in 1 .. N) {
                executor.submit {
                    proxy.ops.simpleReply(ByteArray(1024), 1024)
                    latch.countDown()
                }
            }
            latch.await()
        }
    }

    data class SimpleRPCResult(
            val requestPerSecond: Double,
            val averageIndividualMs: Double,
            val Mbps: Double
    )
//    @Ignore("Run this manually")
    @Test
    fun `measure Megabytes per second for simple RPCs`() {
        warmup()
        val inputOutputSizes = listOf(1024, 4096, 100 * 1024)
        val overallTraffic = 512 * 1024 * 1024L
        measure(inputOutputSizes, (1..5)) { inputOutputSize, N ->
            rpcDriver {
                val maximumQueued = 100

                val numberOfRequests = overallTraffic / (2 * inputOutputSize)
                val executor = Executors.newFixedThreadPool(8)
                val proxy = testProxy(
                        RPCClientConfiguration.default.copy(
                                cacheConcurrencyLevel = 16,
                                observationExecutorPoolSize = 2,
                                producerPoolBound = 2
                        ),
                        RPCServerConfiguration.default.copy(
                                rpcThreadPoolSize = 8,
                                consumerPoolSize = 2,
                                producerPoolBound = 8
                        )
                )
                val remainingLatch = CountDownLatch(numberOfRequests.toInt())
                val queuedCount = AtomicInteger(0)
                val lock = ReentrantLock()
                val canQueueAgain = lock.newCondition()
                val injectorShutdown = AtomicBoolean(false)
                val timings = Collections.synchronizedList(ArrayList<Long>())
                val injector = thread(name = "injector") {
                    while (true) {
                        if (injectorShutdown.get()) break
                        executor.submit {
                            val elapsed = Stopwatch.createStarted().apply {
                                proxy.ops.simpleReply(ByteArray(inputOutputSize), inputOutputSize)
                            }.stop().elapsed(TimeUnit.MICROSECONDS)
                            timings.add(elapsed)
                            if (queuedCount.decrementAndGet() < maximumQueued / 2) {
                                lock.withLock {
                                    canQueueAgain.signal()
                                }
                            }
                            remainingLatch.countDown()
                        }
                        if (queuedCount.incrementAndGet() > maximumQueued) {
                            lock.withLock {
                                canQueueAgain.await()
                            }
                        }
                    }
                }
                val elapsed = Stopwatch.createStarted().apply {
                    remainingLatch.await()
                }.stop().elapsed(TimeUnit.MICROSECONDS)
                injectorShutdown.set(true)
                injector.join()
                executor.shutdownNow()
                SimpleRPCResult(
                        requestPerSecond = 1000000.0 * numberOfRequests.toDouble() / elapsed.toDouble(),
                        averageIndividualMs = timings.average() / 1000.0,
                        Mbps = (overallTraffic.toDouble() / elapsed.toDouble()) * (1000000.0 / (1024.0 * 1024.0))
                )
            }
        }.forEach(::println)
    }

    /**
     * Runs 20k RPCs per second for two minutes and publishes relevant stats to JMX.
     */
    @Ignore("Only use this locally for profiling")
    @Test
    fun `consumption rate`() {
        val metricRegistry = MetricRegistry()
        thread {
            JmxReporter.
                    forRegistry(metricRegistry).
                    inDomain("net.corda").
                    createsObjectNamesWith { _, domain, name ->
                        // Make the JMX hierarchy a bit better organised.
                        val category = name.substringBefore('.')
                        val subName = name.substringAfter('.', "")
                        if (subName == "")
                            ObjectName("$domain:name=$category")
                        else
                            ObjectName("$domain:type=$category,name=$subName")
                    }.
                    build().
                    start()
        }
        rpcDriver {
            val proxy = testProxy(
                    RPCClientConfiguration.default.copy(
                            reapIntervalMs = 100,
                            cacheConcurrencyLevel = 16
                    ),
                    RPCServerConfiguration.default.copy(
                            rpcThreadPoolSize = 4,
                            consumerPoolSize = 4,
                            producerPoolBound = 4
                    )
            )
            measurePerformancePublishMetrics(
                    metricRegistry = metricRegistry,
                    parallelism = 4,
                    overallDurationSecond = 120.0,
                    injectionRatePerSecond = 20000.0,
                    queueSizeMetricName = "$mode.QueueSize",
                    workDurationMetricName = "$mode.WorkDuration",
                    shutdownManager = this.shutdownManager,
                    work = {
                        proxy.ops.simpleReply(ByteArray(4096), 4096)
                    }
            )
        }
    }
}

fun measurePerformancePublishMetrics(
        metricRegistry: MetricRegistry,
        parallelism: Int,
        overallDurationSecond: Double,
        injectionRatePerSecond: Double,
        queueSizeMetricName: String,
        workDurationMetricName: String,
        shutdownManager: ShutdownManager,
        work: () -> Unit
) {
    val workSemaphore = Semaphore(0)
    metricRegistry.register(queueSizeMetricName, Gauge { workSemaphore.availablePermits() })
    val workDurationTimer = metricRegistry.timer(workDurationMetricName)
    val executor = Executors.newSingleThreadScheduledExecutor()
    val workExecutor = Executors.newFixedThreadPool(parallelism)
    val timings = Collections.synchronizedList(ArrayList<Long>())
    for (i in 1 .. parallelism) {
        workExecutor.submit {
            try {
                while (true) {
                    workSemaphore.acquire()
                    workDurationTimer.time {
                        timings.add(
                                Stopwatch.createStarted().apply {
                                    work()
                                }.stop().elapsed(TimeUnit.MICROSECONDS)
                        )
                    }
                }
            } catch (throwable: Throwable) {
                throwable.printStackTrace()
            }
        }
    }
    val injector = executor.scheduleAtFixedRate(
            {
                workSemaphore.release(injectionRatePerSecond.toInt())
            },
            0,
            1,
            TimeUnit.SECONDS
    )
    shutdownManager.registerShutdown {
        injector.cancel(true)
        workExecutor.shutdownNow()
        executor.shutdownNow()
        workExecutor.awaitTermination(1, TimeUnit.SECONDS)
        executor.awaitTermination(1, TimeUnit.SECONDS)
    }
    Thread.sleep((overallDurationSecond * 1000).toLong())
}

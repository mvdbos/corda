package net.corda.node.services.persistence

import net.corda.core.ThreadBox
import net.corda.core.bufferUntilSubscribed
import net.corda.core.crypto.SecureHash
import net.corda.core.flows.StateMachineRunId
import net.corda.core.messaging.SameType
import net.corda.core.node.services.StateMachineRecordedTransactionMappingStorage
import net.corda.core.node.services.StateMachineTransactionMapping
import rx.subjects.PublishSubject
import java.util.*
import javax.annotation.concurrent.ThreadSafe

/**
 * This is a temporary in-memory storage of a state machine id -> txhash mapping
 *
 * TODO persist this instead
 */
@ThreadSafe
class InMemoryStateMachineRecordedTransactionMappingStorage : StateMachineRecordedTransactionMappingStorage {
    private class InnerState {
        val stateMachineTransactionMap = HashMap<StateMachineRunId, HashSet<SecureHash>>()
        val updates = PublishSubject.create<StateMachineTransactionMapping>()!!
    }
    private val mutex = ThreadBox(InnerState())

    override fun addMapping(stateMachineRunId: StateMachineRunId, transactionId: SecureHash) {
        mutex.locked {
            stateMachineTransactionMap.getOrPut(stateMachineRunId) { HashSet() }.add(transactionId)
            updates.onNext(StateMachineTransactionMapping(stateMachineRunId, transactionId))
        }
    }

    override fun track(): SameType<StateMachineTransactionMapping> {
        return mutex.locked {
            SameType(
                    stateMachineTransactionMap.flatMap { entry ->
                        entry.value.map {
                            StateMachineTransactionMapping(entry.key, it)
                        }
                    },
                    updates.bufferUntilSubscribed()
            )
        }
    }
}

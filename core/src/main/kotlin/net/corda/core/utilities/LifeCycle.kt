package net.corda.core.utilities

import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.withLock

class LifeCycle<S : Enum<S>>(initial: S) {
    private val lock = ReentrantReadWriteLock()
    private var state = initial

    fun requireState(requiredState: S) {
        lock.readLock().withLock {
            require(state == requiredState) { "Required state to be $requiredState, was $state" }
        }
    }

    fun transition(from: S, to: S) {
        lock.writeLock().withLock {
            require(state == from) { "Required state to be $from to transition to $to, was $state" }
            state = to
        }
    }
}
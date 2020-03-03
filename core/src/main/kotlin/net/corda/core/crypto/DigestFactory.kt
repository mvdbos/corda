package net.corda.core.crypto

import kotlin.reflect.KClass
import kotlin.reflect.full.createInstance

sealed class Algorithm(val userFriendyName: String, val kClass: KClass<*>) {
    class SHA256 : Algorithm("SHA-256", SHA256Service::class)
    class SHA384 : Algorithm("SHA-384", SHA384Service::class)
}

interface DigestServiceFactory {
    fun getService(algorithm: String): DigestService
}

object DefaultDigestServiceFactory {
    fun getService(algorithm: Algorithm): DigestService {
        return algorithm.kClass.createInstance() as DigestService
    }
}
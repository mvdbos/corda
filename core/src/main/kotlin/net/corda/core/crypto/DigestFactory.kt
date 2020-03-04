package net.corda.core.crypto

import kotlin.reflect.KClass
import kotlin.reflect.full.createInstance

sealed class Algorithm(val userFriendyName: String, val kClass: KClass<*>) {
    class SHA256 : Algorithm("SHA-256", SHA256Service::class)
}

interface DigestServiceFactory {
    fun getService(algorithm: Algorithm): DigestService
}

object DefaultDigestServiceFactory: DigestServiceFactory {
    override fun getService(algorithm: Algorithm): DigestService {
        return algorithm.kClass.createInstance() as DigestService
    }

}
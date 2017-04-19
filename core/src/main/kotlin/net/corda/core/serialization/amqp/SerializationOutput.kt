package net.corda.core.serialization.amqp

import net.corda.core.serialization.SerializedBytes
import org.apache.qpid.proton.codec.Data
import java.io.NotSerializableException
import java.lang.reflect.Type
import java.nio.ByteBuffer
import java.util.*

/**
 * Main entry point for serializing an object to AMQP.
 */
class SerializationOutput(private val serializerFactory: SerializerFactory = SerializerFactory()) {
    // TODO: we're not supporting object refs yet
    private val objectHistory: MutableMap<Any, Int> = IdentityHashMap()
    private val serializerHistory: MutableSet<Serializer> = mutableSetOf()
    private val schemaHistory: MutableSet<TypeNotation> = mutableSetOf()

    @Throws(NotSerializableException::class)
    fun <T : Any> serialize(obj: T): SerializedBytes<T> {
        try {
            val data = Data.Factory.create()
            data.putDescribed()
            data.enter()
            // Descriptor
            data.putObject(Envelope.DESCRIPTOR)
            // Envelope body
            data.putList()
            data.enter()
            // Our object
            writeObject(obj, data)
            // The schema
            data.putObject(Schema(schemaHistory.toList()))
            data.exit() // Exit envelope body
            data.exit() // Exit described
            val bytes = ByteArray(data.encodedSize().toInt() + 8)
            val buf = ByteBuffer.wrap(bytes)
            buf.put(AmqpHeaderV1_0.bytes)
            data.encode(buf)
            return SerializedBytes(bytes)
        } finally {
            objectHistory.clear()
            serializerHistory.clear()
            schemaHistory.clear()
        }
    }

    internal fun writeObject(obj: Any, data: Data) {
        writeObject(obj, data, obj.javaClass)
    }

    internal fun writeObjectOrNull(obj: Any?, data: Data, type: Type) {
        if (obj == null) {
            data.putNull()
        } else {
            writeObject(obj, data, if (type == SerializerFactory.AnyType) obj.javaClass else type)
        }
    }

    internal fun writeObject(obj: Any, data: Data, type: Type) {
        val serializer = serializerFactory.get(obj.javaClass, type)
        if (serializer !in serializerHistory) {
            serializer.writeClassInfo(this)
        }
        serializer.writeObject(obj, data, type, this)
    }

    internal fun writeTypeNotations(vararg typeNotation: TypeNotation): Boolean {
        return schemaHistory.addAll(typeNotation)
    }

    internal fun requireSerializer(type: Type) {
        if (type != SerializerFactory.AnyType) {
            val serializer = serializerFactory.get(null, type)
            if (serializer !in serializerHistory) {
                serializer.writeClassInfo(this)
            }
        }
    }
}


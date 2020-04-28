package net.corda.serialization.djvm.deserializers

import net.corda.core.crypto.CompositeKey
import java.security.PublicKey
import java.util.function.Function

private const val PK_ALGORITHM = 0
private const val PK_FORMAT = 1
private const val PK_ENCODED = 2
private const val PK_UNDERLYING = 3

class PublicKeyWrapper : Function<Array<out Any>, PublicKey> {
    override fun apply(data: Array<out Any>): PublicKey {
        val algorithm = data[PK_ALGORITHM] as String
        val encoded = data[PK_ENCODED] as ByteArray
        return if (algorithm == CompositeKey.Companion.KEY_ALGORITHM) {
            CompositeKey.getInstance(encoded)
        } else {
            WrappedPublicKey(
                algorithm = algorithm,
                format = data[PK_FORMAT] as? String,
                encoded = encoded.clone(),
                hashCode = encoded.contentHashCode(),
                underlying = data[PK_UNDERLYING]
            )
        }
    }
}

private class WrappedPublicKey(
    private val algorithm: String?,
    private val format: String?,
    private val encoded: ByteArray,
    private val hashCode: Int,
    private val underlying: Any
) : PublicKey {
    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        } else if (other !is WrappedPublicKey) {
            return false
        } else {
            return underlying == other.underlying
        }
    }

    override fun hashCode(): Int {
        return hashCode
    }

    override fun getEncoded(): ByteArray {
        return encoded
    }

    override fun getFormat(): String? {
        return format
    }

    override fun getAlgorithm(): String? {
        return algorithm
    }
}
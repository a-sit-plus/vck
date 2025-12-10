package at.asitplus.wallet.lib.data.rfc.tokenStatusList.iso18013


import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.cbor.ByteString

/**
 * Identifier = bstr
 *
 * This only works correctly if the cbor serializer uses `alwaysUseByteString = true`
 * which holds for [coseCompliantSerializer].
 *
 * The `@ByteString` annotation is currently only cosmetic because a custom serializer cannot not honor it
 * due to how it's wired in the backend.
 *
 * We cannot use ByteArray directly because of Kotlin's way of handling equality and kotlinx's handling of `@ByteString`
 */
@Serializable(with = Identifier.TransformingSerializer::class)
data class Identifier(@ByteString val value: ByteArray) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Identifier

        return value.contentEquals(other.value)
    }

    override fun hashCode(): Int = value.contentHashCode()

    object TransformingSerializer : TransformingSerializerTemplate<Identifier, ByteArray>(
        parent = ByteArraySerializer(),
        encodeAs = { it.value },
        decodeAs = { Identifier(it) }
    )
}

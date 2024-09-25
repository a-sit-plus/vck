package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.SerialName
import kotlinx.serialization.cbor.ByteString

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request (8.3.2.1.2.1)
 */
data class IssuerSignedItem(
    @SerialName(PROP_DIGEST_ID)
    val digestId: UInt,
    @SerialName(PROP_RANDOM)
    @ByteString
    val random: ByteArray,
    @SerialName(PROP_ELEMENT_ID)
    val elementIdentifier: String,
    @SerialName(PROP_ELEMENT_VALUE)
    val elementValue: Any,
) {


    fun serialize(namespace: String) = vckCborSerializer.encodeToByteArray(IssuerSignedItemSerializer(namespace), this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as IssuerSignedItem

        if (digestId != other.digestId) return false
        if (!random.contentEquals(other.random)) return false
        if (elementIdentifier != other.elementIdentifier) return false
        if (elementValue is ByteArray && other.elementValue is ByteArray) return elementValue.contentEquals(other.elementValue)
        if (elementValue is IntArray && other.elementValue is IntArray) return elementValue.contentEquals(other.elementValue)
        if (elementValue is BooleanArray && other.elementValue is BooleanArray) return elementValue.contentEquals(other.elementValue)
        if (elementValue is CharArray && other.elementValue is CharArray) return elementValue.contentEquals(other.elementValue)
        if (elementValue is ShortArray && other.elementValue is ShortArray) return elementValue.contentEquals(other.elementValue)
        if (elementValue is LongArray && other.elementValue is LongArray) return elementValue.contentEquals(other.elementValue)
        if (elementValue is FloatArray && other.elementValue is FloatArray) return elementValue.contentEquals(other.elementValue)
        if (elementValue is DoubleArray && other.elementValue is DoubleArray) return elementValue.contentEquals(other.elementValue)
        return if (elementValue is Array<*> && other.elementValue is Array<*>) elementValue.contentDeepEquals(other.elementValue)
        //It was time for Thomas to leave. He had seen everything.
        else elementValue == other.elementValue
    }

    override fun hashCode(): Int {
        var result = digestId.hashCode()
        result = 31 * result + random.contentHashCode()
        result = 31 * result + elementIdentifier.hashCode()
        result = 31 * result + elementValue.hashCode()
        return result
    }

    override fun toString(): String {
        return "IssuerSignedItem(digestId=$digestId," +
                " random=${random.encodeToString(Base16(strict = true))}," +
                " elementIdentifier='$elementIdentifier'," +
                " elementValue=$elementValue)"
    }

    companion object {
        fun deserialize(it: ByteArray, namespace: String) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray(IssuerSignedItemSerializer(namespace), it)
        }.wrap()

        internal const val PROP_DIGEST_ID = "digestID"
        internal const val PROP_RANDOM = "random"
        internal const val PROP_ELEMENT_ID = "elementIdentifier"
        internal const val PROP_ELEMENT_VALUE = "elementValue"
    }
}
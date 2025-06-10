package at.asitplus.wallet.lib.iso

import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.contentHashCodeIfArray
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
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

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as IssuerSignedItem

        if (digestId != other.digestId) return false
        if (!random.contentEquals(other.random)) return false
        if (elementIdentifier != other.elementIdentifier) return false
        if (!elementValue.contentEqualsIfArray(other.elementValue)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = digestId.hashCode()
        result = 31 * result + random.contentHashCode()
        result = 31 * result + elementIdentifier.hashCode()
        result = 31 * result + elementValue.contentHashCodeIfArray()
        return result
    }

    override fun toString(): String = "IssuerSignedItem(digestId=$digestId," +
            " random=${random.encodeToString(Base16Strict)}," +
            " elementIdentifier='$elementIdentifier'," +
            " elementValue=${elementValue.toCustomString()})"

    companion object {
        internal const val PROP_DIGEST_ID = "digestID"
        internal const val PROP_RANDOM = "random"
        internal const val PROP_ELEMENT_ID = "elementIdentifier"
        internal const val PROP_ELEMENT_VALUE = "elementValue"
    }
}

private fun Any.toCustomString(): String = when (this) {
    is ByteArray -> this.encodeToString(Base16Strict)
    is Array<*> -> this.contentDeepToString()
    else -> this.toString()
}

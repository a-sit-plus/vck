package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.SerialName


data class ZkSignedItem(
    @SerialName(PROP_ELEMENT_ID)
    override val elementIdentifier: String,

    @SerialName(PROP_ELEMENT_VALUE)
    override val elementValue: Any,
) : Item {
    override fun toString(): String = "ZkSignedItem(elementIdentifier='$elementIdentifier'," +
            " elementValue=${elementValue.toCustomString()})"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ZkSignedItem) return false

        if (elementIdentifier != other.elementIdentifier) return false

        return areValuesEqual(elementValue, other.elementValue)
    }

    override fun hashCode(): Int {
        var result = elementIdentifier.hashCode()
        result = 31 * result + valueHashCode(elementValue)
        return result
    }

    companion object {
        internal const val PROP_ELEMENT_ID = "elementIdentifier"
        internal const val PROP_ELEMENT_VALUE = "elementValue"
    }
}

private fun areValuesEqual(a: Any, b: Any): Boolean = when (a) {
    is ByteArray if b is ByteArray -> a.contentEquals(b)
    is Array<*> if b is Array<*> -> a.contentDeepEquals(b)
    else -> a == b
}

private fun valueHashCode(value: Any): Int = when (value) {
    is ByteArray -> value.contentHashCode()
    is Array<*> -> value.contentDeepHashCode()
    else -> value.hashCode()
}

private fun Any.toCustomString(): String = when (this) {
    is ByteArray -> this.encodeToString(Base16Strict)
    is Array<*> -> this.contentDeepToString()
    else -> this.toString()
}
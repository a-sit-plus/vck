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

    companion object {
        internal const val PROP_ELEMENT_ID = "elementIdentifier"
        internal const val PROP_ELEMENT_VALUE = "elementValue"
    }
}

private fun Any.toCustomString(): String = when (this) {
    is ByteArray -> this.encodeToString(Base16Strict)
    is Array<*> -> this.contentDeepToString()
    else -> this.toString()
}
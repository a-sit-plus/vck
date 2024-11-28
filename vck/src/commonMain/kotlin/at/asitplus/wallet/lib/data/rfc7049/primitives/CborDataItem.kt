package at.asitplus.wallet.lib.data.rfc7049.primitives

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

// TODO: add serializer using lookahead to detect type? Is this even possible?
@Serializable
sealed interface CborDataItem {
    // TODO: this cannot represent the full range that cbor is capable of
    @Serializable
    @JvmInline
    value class Integer(val value: Long) : CborDataItem
    // TODO: this probably serialized NegativeInteger incorrectly
//    @JvmInline
//    value class UnsignedInteger(val value: ULong) : CborDataItem
//    @JvmInline
//    value class NegativeInteger(
//        private val cborSerialized: ULong
//    ) : CborDataItem {
//        init {
//            validate(cborSerialized)
//        }
//
//        val value: ULong
//            get() = (cborSerialized + 1)
//
//        companion object {
//            fun validate(cborSerialized: ULong) {
//                if(cborSerialized == ULong.MAX_VALUE) {
//                    throw IllegalArgumentException("Value is in principle a valid argument, but too big to be supported by the implementation.")
//                }
//            }
//        }
//    }

    @Serializable
    @JvmInline
    value class ByteString(
        @kotlinx.serialization.cbor.ByteString
        val value: ByteArray
    ) : CborDataItem

    @Serializable
    @JvmInline
    value class TextString(val value: String) : CborDataItem

//    // TODO: this is surely serialized incorrectly
//    @Serializable
//    data class TaggedItem(
//        val tag: ULong,
//        val content: CborDataItem,
//    ) : CborDataItem

    @Serializable
    @JvmInline
    value class DataItemArray(val value: List<CborDataItem>) : CborDataItem

    @Serializable
    @JvmInline
    value class DataItemMap(val value: List<Pair<CborDataItem, CborDataItem>>) : CborDataItem

//  TODO: is this even relevant?
//    @Serializable
//    @JvmInline
//    value class Tag(val value: ULong) : CborDataItem

    // TODO: find kotlin equivalent
//    @Serializable
//    @JvmInline
//    value class HalfPrecisionFloat(val value: Float) : CborDataItem
    @Serializable
    @JvmInline
    value class SinglePrecisionFloat(val value: Float) : CborDataItem

    @Serializable
    @JvmInline
    value class DoublePrecisionFloat(val value: Double) : CborDataItem

    @JvmInline
    value class True private constructor(val value: Boolean = true) : CborDataItem {
        companion object {
            val INSTNACE = True()
        }
    }

    @JvmInline
    value class False private constructor(val value: Boolean = false) : CborDataItem {
        companion object {
            val INSTNACE = False()
        }
    }

    @JvmInline
    value class Null private constructor(val value: Unit? = null) : CborDataItem {
        companion object {
            val INSTNACE = Null()
        }
    }

    // TODO: find kotlin equivalent
//    @JvmInline
//    value class Undefined private constructor(val value: Nothing) : CborDataItem {
//        companion object {
//            val INSTNACE = Undefined()
//        }
//    }

    // TODO: find kotlin equivalent
//    @JvmInline
//    value class Break private constructor(val value: Unit? = null) : CborDataItem {
//        companion object {
//            val INSTNACE = Null()
//        }
//    }
}
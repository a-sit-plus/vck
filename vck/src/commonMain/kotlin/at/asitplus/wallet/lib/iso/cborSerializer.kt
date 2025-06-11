package at.asitplus.wallet.lib.iso

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.CompositeEncoder
import okio.ByteString.Companion.toByteString

@OptIn(ExperimentalSerializationApi::class)
@Deprecated("No added value", ReplaceWith("at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer"))
val vckCborSerializer by lazy {
    Cbor(from = at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer) {
        ignoreUnknownKeys = true
        alwaysUseByteString = true
        encodeDefaults = false
    }
}

@Deprecated("Moved", ReplaceWith("at.asitplus.iso.cborSerializer.ByteArray.stripCborTag"))
fun ByteArray.stripCborTag(tag: Byte): ByteArray {
    val tagBytes = byteArrayOf(0xd8.toByte(), tag)
    return if (this.take(tagBytes.size).toByteArray().contentEquals(tagBytes)) {
        this.drop(tagBytes.size).toByteArray()
    } else {
        this
    }
}

@Deprecated("Moved", ReplaceWith("at.asitplus.iso.cborSerializer.ByteArray.wrapInCborTag"))
fun ByteArray.wrapInCborTag(tag: Byte) = byteArrayOf(0xd8.toByte()) + byteArrayOf(tag) + this

fun ByteArray.sha256(): ByteArray = toByteString().sha256().toByteArray()
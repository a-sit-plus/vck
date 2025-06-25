package at.asitplus.wallet.lib.iso

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.supreme.hash.digest
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.cbor.Cbor

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

fun ByteArray.sha256(): ByteArray = Digest.SHA256.digest(this)
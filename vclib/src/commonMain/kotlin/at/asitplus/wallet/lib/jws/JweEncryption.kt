package at.asitplus.wallet.lib.jws

import kotlinx.serialization.Serializable

@Serializable(with = JweEncryptionSerializer::class)
enum class JweEncryption(val text: String) {

    A256GCM("A256GCM");

    val encryptionKeyLength
        get() = when (this) {
            A256GCM -> 256
        }

    val ivLengthBits
        get() = when (this) {
            A256GCM -> 128
        }

}


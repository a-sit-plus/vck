package at.asitplus.wallet.lib.iso

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.cbor.Cbor

@OptIn(ExperimentalSerializationApi::class)
val cborSerializer by lazy {
    Cbor {
        ignoreUnknownKeys = true
        alwaysUseByteString = true
        encodeDefaults = false
    }
}
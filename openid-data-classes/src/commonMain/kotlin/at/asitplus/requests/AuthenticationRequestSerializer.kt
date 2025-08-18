package at.asitplus.requests

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object AuthenticationRequestSerializer : KSerializer<AuthenticationRequest> {
    override val descriptor: SerialDescriptor
        get() = TODO("Not yet implemented")

    override fun serialize(
        encoder: Encoder,
        value: AuthenticationRequest
    ) {
        TODO("Not yet implemented")
    }

    override fun deserialize(decoder: Decoder): AuthenticationRequest {
        TODO("Not yet implemented")
    }
}
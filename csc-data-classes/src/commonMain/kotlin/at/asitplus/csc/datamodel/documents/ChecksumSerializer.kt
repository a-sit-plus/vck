package at.asitplus.csc.datamodel.documents

import at.asitplus.csc.datamodel.basic.Hash
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.io.Base64Strict
import io.ktor.util.*
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder


object ChecksumSerializer : KSerializer<Hash> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("Hash", PrimitiveKind.STRING)

    override fun serialize(
        encoder: Encoder,
        value: Hash
    ) {
        encoder.encodeString(
            "${value.digest.name.toLowerCasePreservingASCIIRules()}-${
                value.value.encodeToString(
                    Base64Strict
                )
            }"
        )
    }

    override fun deserialize(decoder: Decoder): Hash {
        val (oidString, valueString) = decoder.decodeString().split("-")
            .also { require(it.size == 2) { "Invalid hash format: $it" } }
        return Hash(valueString.decodeToByteArray(Base64Strict), ObjectIdentifier(oidString))
    }

}
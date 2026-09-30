package at.asitplus.csc.datamodel.documents

import at.asitplus.csc.datamodel.basic.Hash
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import io.ktor.util.*
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.base64.Base64ConfigBuilder
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder


/** CSC Data Model Bindings v1.0.0 requires W3C Subresource Integrity format, Base64 and no padding */
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
                    Base64NoPaddingStrict
                )
            }"
        )
    }

    override fun deserialize(decoder: Decoder): Hash {
        val (digestName, valueString) = decoder.decodeString().split("-")
            .also { require(it.size == 2) { "Invalid hash format: $it" } }
        return Hash(valueString.decodeToByteArray(Base64NoPaddingStrict), Digest.entries.first { it.name.toLowerCasePreservingASCIIRules() == digestName }.oid)
    }

    private val Base64NoPaddingStrict = Base64(config = Base64ConfigBuilder().apply {
        lineBreakInterval = 0
        encodeToUrlSafe = false
        isLenient = false
        padEncoded = false
    }.build())

}
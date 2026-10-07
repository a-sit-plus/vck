package at.asitplus.csc.datamodel.documents

import at.asitplus.csc.datamodel.basic.Hash
import at.asitplus.signum.indispensable.digest.WellKnownDigest
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


/**
 * Serializes a [Hash] as the W3C Subresource Integrity string used by CSC Data Model Bindings 1.0.0
 * `qesRequest.checksum`, for example `sha256-BwgJ` (digest name, hyphen, unpadded standard Base64).
 * This is not the structured `Hash` object used for CSC Data Model `DocumentReference.checksum`.
 */
object ChecksumSerializer : KSerializer<Hash> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("Hash", PrimitiveKind.STRING)

    override fun serialize(
        encoder: Encoder,
        value: Hash
    ) {
        val digest = requireNotNull(value.digest) { "Unsupported checksum algorithm OID: ${value.algorithmOid}" }
        encoder.encodeString(
            "${digest.name.toLowerCasePreservingASCIIRules()}-${
                value.value.encodeToString(
                    Base64NoPaddingStrict
                )
            }"
        )
    }

    override fun deserialize(decoder: Decoder): Hash {
        val (digestName, valueString) = decoder.decodeString().split("-")
            .also { require(it.size == 2) { "Invalid hash format: $it" } }
        return Hash(
            valueString.decodeToByteArray(Base64NoPaddingStrict),
            WellKnownDigest.entries.first { it.name.toLowerCasePreservingASCIIRules() == digestName }.oid
        )
    }

    private val Base64NoPaddingStrict = Base64(config = Base64ConfigBuilder().apply {
        lineBreakInterval = 0
        encodeToUrlSafe = false
        isLenient = false
        padEncoded = false
    }.build())

}

package at.asitplus.csc.datamodel.documents

import at.asitplus.csc.datamodel.basic.Hash
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.io.Base64Strict
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
 * Codec for the SRI checksum string specified by CSC Data Model Bindings 1.0.0 §7.1.2, for example
 * `sha256-BwgJ` (digest name, hyphen, Base64 without padding). It is retained to document and expose the CSC wire
 * representation. VC-K's QES wire models follow the conflicting structured [Hash] representation from ETSI TS 119
 * 432 instead, so this serializer intentionally has no call sites in the project (yet).
 */
@Suppress("unused")
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
                    Base64Strict
                )
            }"
        )
    }

    override fun deserialize(decoder: Decoder): Hash {
        val (digestName, valueString) = decoder.decodeString().split("-")
            .also { require(it.size == 2) { "Invalid hash format: $it" } }
        return Hash(
            valueString.decodeToByteArray(Base64Strict),
            Digest.entries.first { it.name.toLowerCasePreservingASCIIRules() == digestName }.oid
        )
    }

    // TODO: Although theoretically defined like this, no one actually uses no padding so we cannot either.
    @Suppress("unused")
    private val Base64NoPaddingStrict = Base64(config = Base64ConfigBuilder().apply {
        lineBreakInterval = 0
        encodeToUrlSafe = false
        isLenient = false
        padEncoded = false
    }.build())
}

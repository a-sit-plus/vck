package at.asitplus.wallet.sdjwt

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = SelectiveDisclosureConstraints.SelectiveDisclosureConstraintsSerializer::class)
enum class SelectiveDisclosureConstraints(val identifier: String) {
    /** The Issuer MUST make the claim selectively disclosable. */
    ALWAYS("always"),

    /** The Issuer MAY make the claim selectively disclosable. */
    ALLOWED("allowed"),

    /** The Issuer MUST NOT make the claim selectively disclosable. */
    NEVER("never"),
    ;

    /**
     * An extending type can specify an sd property for a claim that is marked as allowed in the extended type
     * (or where sd was omitted), changing it to either always or never. However, it MUST NOT change a claim that is
     * marked as always or never in the extended type to a different value.
     */
    fun extendFrom(
        base: SelectiveDisclosureConstraints
    ) = when (base) {
        ALLOWED -> this // do whatever
        else -> base.also { // retain otherwise
            require(this == base) {
                "Expected child to preserve selective disclosure constraint `$base`, but got `$this`."
            }
        }
    }

    class SelectiveDisclosureConstraintsSerializer : KSerializer<SelectiveDisclosureConstraints> {

        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor("ClaimSelectiveDisclosable", PrimitiveKind.STRING)

        override fun serialize(encoder: Encoder, value: SelectiveDisclosureConstraints) {
            encoder.encodeString(value.identifier)
        }

        override fun deserialize(decoder: Decoder): SelectiveDisclosureConstraints {
            val decoded = decoder.decodeString()
            return SelectiveDisclosureConstraints.entries.first { it.identifier == decoded }
        }
    }
}
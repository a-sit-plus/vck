package at.asitplus.etsi

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject

@Serializable(with = PolicyOrLegalNoticeItem.Serializer::class)
data class PolicyOrLegalNoticeItem(
    /** Localized text of the scheme policy or relevant legal notice (TS 119 602, 6.3.11). */
    val legalNotice: MultilingualCharacterString? = null,
    /** Localized pointer to the scheme policy or relevant legal notice (TS 119 602, 6.3.11). */
    val policy: MultilingualPointer? = null,
    /**
     * Text of the relevant legal notice without a language. The Annex A.1 JSON schema of TS 119 602 declares
     * `LoTELegalNotice` as a plain string, which conflicts with 6.3.11, but published lists use it.
     */
    val legalNoticeText: String? = null,
) {
    init {
        require(listOfNotNull(legalNotice, policy, legalNoticeText).size == 1) {
            "Expected either a legal notice or a policy pointer."
        }
    }

    object SerialNames {
        /** Wire member name `LoTEPolicy`. */
        const val POLICY = "LoTEPolicy"
        /** Wire member name `LoTELegalNotice`. */
        const val LEGAL_NOTICE = "LoTELegalNotice"
    }

    /** Encodes [legalNoticeText] and [legalNotice] both as `LoTELegalNotice`, as a string or an object. */
    object Serializer : KSerializer<PolicyOrLegalNoticeItem> {
        override val descriptor: SerialDescriptor =
            buildClassSerialDescriptor("at.asitplus.etsi.PolicyOrLegalNoticeItem") {
                element(SerialNames.LEGAL_NOTICE, JsonElement.serializer().descriptor, isOptional = true)
                element(SerialNames.POLICY, MultilingualPointer.serializer().descriptor, isOptional = true)
            }

        override fun serialize(encoder: Encoder, value: PolicyOrLegalNoticeItem) {
            val json = (encoder as? JsonEncoder)?.json
                ?: throw SerializationException("PolicyOrLegalNoticeItem is only supported in JSON")
            encoder.encodeJsonElement(buildJsonObject {
                value.legalNotice?.let {
                    put(SerialNames.LEGAL_NOTICE, json.encodeToJsonElement(MultilingualCharacterString.serializer(), it))
                }
                value.legalNoticeText?.let { put(SerialNames.LEGAL_NOTICE, JsonPrimitive(it)) }
                value.policy?.let {
                    put(SerialNames.POLICY, json.encodeToJsonElement(MultilingualPointer.serializer(), it))
                }
            })
        }

        override fun deserialize(decoder: Decoder): PolicyOrLegalNoticeItem {
            val json = (decoder as? JsonDecoder)?.json
                ?: throw SerializationException("PolicyOrLegalNoticeItem is only supported in JSON")
            val members = decoder.decodeJsonElement().jsonObject
            val notice = members[SerialNames.LEGAL_NOTICE]?.takeUnless { it == JsonNull }
            return PolicyOrLegalNoticeItem(
                legalNotice = notice?.takeUnless { it is JsonPrimitive }
                    ?.let { json.decodeFromJsonElement(MultilingualCharacterString.serializer(), it) },
                policy = members[SerialNames.POLICY]?.takeUnless { it == JsonNull }
                    ?.let { json.decodeFromJsonElement(MultilingualPointer.serializer(), it) },
                legalNoticeText = (notice as? JsonPrimitive)?.let {
                    if (!it.isString) throw SerializationException("Expected a string or an object as legal notice: $it")
                    it.content
                },
            )
        }
    }
}

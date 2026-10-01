package at.asitplus.openid

import kotlinx.serialization.Serializable

@Deprecated("Support for SIOPv2 has been removed")
@Serializable(with = IdTokenTypeSerializer::class)
enum class IdTokenType(val text: String) {

    SUBJECT_SIGNED("subject_signed_id_token"),
    ATTESTER_SIGNED("attester_signed_id_token")

}
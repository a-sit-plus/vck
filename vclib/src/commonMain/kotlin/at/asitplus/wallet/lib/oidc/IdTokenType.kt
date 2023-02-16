package at.asitplus.wallet.lib.oidc

import kotlinx.serialization.Serializable

@Serializable(with = IdTokenTypeSerializer::class)
enum class IdTokenType(val text: String) {

    SUBJECT_SIGNED("subject_signed"),
    ATTESTER_SIGNED("attester_signed")

}
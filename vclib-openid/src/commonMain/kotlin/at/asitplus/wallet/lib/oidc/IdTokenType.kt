package at.asitplus.wallet.lib.oidc

enum class IdTokenType(val text: String) {

    SUBJECT_SIGNED("subject_signed_id_token"),
    ATTESTER_SIGNED("attester_signed_id_token")

}
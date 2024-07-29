package at.asitplus.wallet.lib.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Implementation of [W3C RevocationList2020](https://w3c-ccg.github.io/vc-status-rl-2020/) for use in a [VerifiableCredential].
 */
@Serializable
data class CredentialStatus(
    @SerialName("id")
    val id: String,
    @SerialName("type")
    val type: String,
    @SerialName("revocationListIndex")
    val index: Long,
    @SerialName("revocationListCredential")
    val statusListUrl: String,
) {
    constructor(credential: String, index: Long) : this(
        id = "$credential#$index",
        type = "RevocationList2020Status",
        index,
        credential
    )
}
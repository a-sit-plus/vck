package at.asitplus.wallet.lib.oidvci

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


@Serializable
data class CredentialSubjectMetadataSingle(
    @SerialName("mandatory")
    val mandatory: Boolean? = null,

    @SerialName("value_type")
    val valueType: String? = null,

    @SerialName("display")
    val display: DisplayProperties? = null,
)


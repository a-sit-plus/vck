package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.data.CredentialSubject
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
@SerialName("EudiwPid1")
data class EudiwPid1(
    override val id: String,

    @SerialName("family_name")
    val familyName: String,
) : CredentialSubject()
package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ETSI TS 119 472-2 V1.3.1 RegistrarInfo
 * See member `euWrpRegistrarInfo` of `DocRequestInfo`.
 */
@Serializable
data class WrpRegistrarInfo(
    @SerialName("identifier")
    val identifier: List<WrpIdentifier>,

    @SerialName("srvDescription")
    val srvDescription: List<WrpLangString>,

    @SerialName("registryURI")
    val registryURI: String,

    @SerialName("intendedUseIdentifier")
    val intendedUseIdentifier: String,

    @SerialName("purpose")
    val purpose: List<WrpLangString>,

    @SerialName("policyURI")
    val policyURI: String,

    @SerialName("credential")
    val credential: List<WrpClaim>? = null,
)


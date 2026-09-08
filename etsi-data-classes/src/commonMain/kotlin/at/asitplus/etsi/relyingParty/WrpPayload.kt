package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * WRPRC payload aligned to ETSI TS 119 475 V1.2.1 Annex C.
 */
@Serializable
data class WrpPayload(
    @SerialName("name")
    val name: String? = null,

    @SerialName("sub_ln")
    val subLn: String? = null,

    @SerialName("sub_gn")
    val subGn: String? = null,

    @SerialName("sub_fn")
    val subFn: String? = null,

    @SerialName("sub")
    val sub: String,

    @SerialName("country")
    val country: String,

    @SerialName("registry_uri")
    val registryUri: String,

    @SerialName("srv_description")
    val srvDescription: List<List<WrpLangString>>,

    @SerialName("entitlements")
    val entitlements: List<String>,

    @SerialName("privacy_policy")
    val privacyPolicy: String,

    @SerialName("info_uri")
    val infoUri: String,

    @SerialName("support_uri")
    val supportUri: String? = null,

    @SerialName("supervisory_authority")
    val supervisoryAuthority: WrpSupervisoryAuthority? = null,

    @SerialName("policy_id")
    val policyId: List<String> = emptyList(),

    @SerialName("certificate_policy")
    val certificatePolicy: String,

    @SerialName("iat")
    val iat: Long,

    @SerialName("status")
    val status: WrpStatus,

    @SerialName("purpose")
    val purpose: List<WrpLangString> = emptyList(),

    @SerialName("credentials")
    val credentials: List<WrpCredential> = emptyList(),

    @SerialName("intended_use_id")
    val intendedUseId: String? = null,

    @SerialName("provides_attestations")
    val providesAttestations: List<WrpCredential> = emptyList(),

    @SerialName("public_body")
    val publicBody: Boolean? = null,

    @SerialName("intermediary")
    val intermediary: WrpIntermediary? = null,

    @SerialName("exp")
    val exp: Long? = null,
)

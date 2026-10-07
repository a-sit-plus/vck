package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ETSI TS 119 472-2 V1.3.1 RegistrarInfo
 * See member `euWrpRegistrarInfo` of `DocRequestInfo`.
 * Attribute definitions refer to ETSI TS 119 475 V1.2.1 Annex B.
 */
@Serializable
data class WrpRegistrarInfo(
    /** Officially recorded identifiers of the relying party (clauses B.2.2 and B.2.5). */
    @SerialName("identifier")
    val identifier: List<WrpIdentifier>,

    /** Localized descriptions of the services provided by the relying party (clause B.2.1). */
    @SerialName("srvDescription")
    val srvDescription: List<WrpLangString>,

    /** URL of the national registry API for the registered relying party (clause B.2.1). */
    @SerialName("registryURI")
    val registryURI: String,

    /** Registrar-provided unique identifier of the registered intended use (clause B.2.7). */
    @SerialName("intendedUseIdentifier")
    val intendedUseIdentifier: String,

    /** Localized purposes of the intended data processing (clause B.2.7). */
    @SerialName("purpose")
    val purpose: List<WrpLangString>,

    /** URL at which the privacy policy for the intended use is published (clauses B.2.7 and B.2.8). */
    @SerialName("policyURI")
    val policyURI: String,

    /** Attestations potentially requestable within the registered intended use (clause B.2.7). */
    @SerialName("credential")
    val credential: List<WrpCredential>? = null,
)

package at.asitplus.etsi.relyingParty

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * The registration information of a PID or attestation provider, provided by its registrar, in the element of format
 * `registrar_dataset` of `issuer_info` in its issuer metadata (ETSI TS 119 472-3 V1.1.1, 4.2.3). Attribute
 * definitions refer to ETSI TS 119 475 V1.2.1 Annex B.
 */
@Serializable
data class WrpRegistrarDataset(
    /** Identifiers of the provider (ISS-MDATA-REG_CERT-4.2.3-10, clauses B.2.2 and B.2.5). */
    @SerialName("identifier")
    val identifier: List<WrpIdentifier>,

    /** Registered user-friendly descriptions of the service of the provider (ISS-MDATA-REG_CERT-4.2.3-11). */
    @SerialName("srvDescription")
    val srvDescription: List<WrpMultiLangString>,

    /** URI of the registrar of the provider (ISS-MDATA-REG_CERT-4.2.3-12, clause B.2.1). */
    @SerialName("registryURI")
    val registryURI: String,

    /** The attestation types the provider intends to issue (ISS-MDATA-REG_CERT-4.2.3-13, clause B.2.9). */
    @SerialName("providesAttestations")
    val providesAttestations: List<WrpCredential>,
)

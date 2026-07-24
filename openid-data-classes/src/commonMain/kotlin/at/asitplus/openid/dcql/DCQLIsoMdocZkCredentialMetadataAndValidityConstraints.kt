package at.asitplus.openid.dcql

import at.asitplus.KmmResult
import at.asitplus.catching
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DCQLIsoMdocZkCredentialMetadataAndValidityConstraints(
    /**
     * OID4VP 1.0 B.2.3: doctype_value: REQUIRED. String that specifies an allowed value for the
     * doctype of the requested Verifiable Credential. It MUST be a valid doctype identifier as
     * defined in [ISO.18013-5].
     */
    @SerialName(SerialNames.DOCTYPE_VALUE)
    val doctypeValue: String,

    /**
     * Extended ISO Mdoc metadata with Longfellow ZK support (Vendor extension)
     * See https://google.github.io/longfellow-zk/docs/protocols/
     */
    @SerialName(SerialNames.ZK_SYSTEM_TYPE)
    val zkSystemType: DCQLIsoMdocZkSystemType,

    ) : DCQLCredentialMetadataAndValidityConstraints {
    object SerialNames {
        const val DOCTYPE_VALUE = "doctype_value"
        const val ZK_SYSTEM_TYPE = "zk_system_type"
    }

    fun validateCredentialConformance(credential: DCQLIsoMdocCredential): KmmResult<Unit> = validate(
        actualDoctypeValue = credential.documentType,
    )

    fun validate(actualDoctypeValue: String?): KmmResult<Unit> = catching {
        require(actualDoctypeValue == doctypeValue) {
            "Incompatible MDOC document type."
        }
        zkSystemType.validate()
    }
}
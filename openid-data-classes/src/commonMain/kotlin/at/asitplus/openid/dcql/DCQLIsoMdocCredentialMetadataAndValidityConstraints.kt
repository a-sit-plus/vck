package at.asitplus.openid.dcql

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.data.NonEmptyList
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DCQLIsoMdocCredentialMetadataAndValidityConstraints(
    /**
     * OID4VP 1.0 B.2.3: doctype_value: REQUIRED. String that specifies an allowed value for the
     * doctype of the requested Verifiable Credential. It MUST be a valid doctype identifier as
     * defined in [ISO.18013-5].
     */
    @SerialName(SerialNames.DOCTYPE_VALUE)
    val doctypeValue: String,

    // TODO: Think about creating a DCQLIsoMdocZkCredentialMetadataAndValidityConstraints class instead
    /**
     * Extended ISO Mdoc metadata with Longfellow ZK support (Vendor extension)
     * See https://github.com/google/longfellow-zk/blob/main/docs/content/en/docs/zk-system-spec.md
     */
    @SerialName(SerialNames.ZK_SYSTEM_TYPE)
    val zkSystemType: List<DCQLZkSystemType>? = null,

    ) : DCQLCredentialMetadataAndValidityConstraints {
    object SerialNames {
        const val DOCTYPE_VALUE = "doctype_value"
        const val ZK_SYSTEM_TYPE = "zk_system_type"
    }

    fun validate(actualDoctypeValue: String?): KmmResult<Unit> = catching {
        if (actualDoctypeValue != doctypeValue) {
            throw IllegalArgumentException("Incompatible MDOC document type.")
        }
        zkSystemType?.let { zkTypes ->
            if (zkTypes.isEmpty()) {
                throw IllegalArgumentException("No acceptable zero knowledge system types provided.")
            }
            val ids = zkTypes.map { it.id }
            if (ids.size != ids.distinct().size) {
                throw IllegalArgumentException("zkSystemType ids must be unique in the list of ids ($ids)")
            }
        }
    }
}
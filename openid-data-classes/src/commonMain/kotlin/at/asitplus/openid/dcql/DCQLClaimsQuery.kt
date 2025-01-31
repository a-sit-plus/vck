package at.asitplus.openid.dcql

import at.asitplus.KmmResult
import at.asitplus.catching
import kotlinx.serialization.Serializable

@Serializable(with = DCQLClaimsQuerySerializer::class)
interface DCQLClaimsQuery {
    /**
     * OID4VP draft 23: id: REQUIRED if claim_sets is present in the Credential Query; OPTIONAL
     * otherwise. A string identifying the particular claim. The value MUST be a non-empty string
     * consisting of alphanumeric, underscore (_) or hyphen (-) characters. Within the particular
     * claims array, the same id MUST NOT be present more than once.
     */
    val id: DCQLClaimsQueryIdentifier?

    /**
     * OID4VP draft 23: values: OPTIONAL. An array of strings, integers or boolean values that
     * specifies the expected values of the claim. If the values property is present, the Wallet
     * SHOULD return the claim only if the type and value of the claim both match for at least one
     * of the elements in the array. Details of the processing rules are defined in Section 6.3.1.1.
     */
    val values: List<DCQLExpectedClaimValue>?

    object SerialNames {
        const val ID = "id"
        const val VALUES = "values"
    }

    fun <Credential : Any> executeClaimsQueryAgainstCredential(
        credentialQuery: DCQLCredentialQuery,
        credential: Credential,
        credentialStructureExtractor: (Credential) -> DCQLCredentialClaimStructure,
    ): KmmResult<DCQLClaimsQueryResult> = catching {
        when (this) {
            is DCQLJsonClaimsQuery -> {
                executeJsonClaimsQueryAgainstCredential(
                    credentialQuery = credentialQuery,
                    credential = credential,
                    credentialStructureExtractor = {
                        credentialStructureExtractor(it) as DCQLCredentialClaimStructure.JsonBasedStructure
                    }
                ).getOrThrow().also {
                    if(it.nodeList.isEmpty()) {
                        throw IllegalStateException("Credential does not satisfy claims query.")
                    }
                }
            }

            is DCQLIsoMdocClaimsQuery -> {
                executeIsoMdocClaimsQueryAgainstCredential(
                    credentialQuery = credentialQuery,
                    credential = credential,
                    credentialStructureExtractor = {
                        credentialStructureExtractor(it) as DCQLCredentialClaimStructure.IsoMdocStructure
                    }
                ).getOrThrow()
            }

            else -> throw IllegalStateException("Unsupported claim query type")
        }
    }
}


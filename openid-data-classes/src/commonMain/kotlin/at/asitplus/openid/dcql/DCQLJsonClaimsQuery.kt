package at.asitplus.openid.dcql

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.CredentialFormatEnum
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

@Serializable
data class DCQLJsonClaimsQuery(
    @SerialName(DCQLClaimsQuery.SerialNames.ID)
    override val id: DCQLClaimsQueryIdentifier? = null,
    @SerialName(DCQLClaimsQuery.SerialNames.VALUES)
    override val values: List<DCQLExpectedClaimValue>? = null,

    /**
     * OID4VP draft 23: path: REQUIRED if the Credential Format uses a JSON-based claims structure
     * (e.g., IETF SD-JWT VC and W3C Verifiable Credentials); MUST NOT be present otherwise. The
     * value MUST be a non-empty array representing a claims path pointer that specifies the path
     * to a claim within the Verifiable Credential, as defined in Section 6.4.
     */
    @SerialName(SerialNames.PATH)
    val path: DCQLClaimsPathPointer,
) : DCQLClaimsQuery {
    object SerialNames {
        const val PATH = "path"
    }

    /**
     *  6.3.1.1. Selecting Claims
     *
     * The following rules apply for selecting claims via claims and claim_sets:
     * If claims is absent, the Verifier requests all claims existing in the Credential.
     * If claims is present, but claim_sets is absent, the Verifier requests all claims listed in
     * claims. If both claims and claim_sets are present, the Verifier requests one combination of
     * the claims listed in claim_sets. The order of the options conveyed in the claim_sets array
     * expresses the Verifier's preference for what is returned; the Wallet MUST return the first
     * option that it can satisfy. If the Wallet cannot satisfy any of the options, it MUST NOT
     * return any claims.When a Claims Query contains a restriction on the values of a claim, the
     * Wallet SHOULD NOT return the claim if its value does not match at least one of the elements
     * in values i.e., the claim should be treated the same as if it did not exist in the
     * Credential. Implementing this restriction may not be possible in all cases, for example,
     * if the Wallet does not have access to the claim value before presentation or user consent or
     * if another component routing the request to the Wallet does not have access to the claim
     * value. Therefore, Verifiers must treat restrictions expressed using values as a best-effort
     * way to improve user privacy, but MUST NOT rely on it for security checks.The purpose of the
     * claim_sets syntax is to provide a way for a verifier to describe alternative ways a given
     * credential can satisfy the request. The array ordering expresses the Verifier's preference
     * for how to fulfill the request. The first element in the array is the most preferred and the
     * last element in the array is the least preferred. Verifiers SHOULD use the principle of
     * least information disclosure to influence how they order these options. For example, a proof
     * of age request should prioritize requesting an attribute like age_over_18 over an attribute
     * like birth_date. The claim_sets syntax is not intended to define options the user can choose
     * from, see Section 6.3.1.3 for more information.If the Wallet cannot deliver all claims
     * requested by the Verifier according to these rules, it MUST NOT return the respective
     * Credential.
     */
    fun <Credential : Any> executeJsonClaimsQueryAgainstCredential(
        credentialQuery: DCQLCredentialQuery,
        credential: Credential,
        credentialStructureExtractor: (Credential) -> DCQLCredentialClaimStructure.JsonBasedStructure,
        jsonBasedCredentialFormats: List<CredentialFormatEnum> = listOf(
            CredentialFormatEnum.VC_SD_JWT,
            CredentialFormatEnum.JWT_VC,
        )
    ): KmmResult<DCQLClaimsQueryResult> = catching {
        if (credentialQuery.format !in jsonBasedCredentialFormats) {
            throw IllegalArgumentException("Inconsistent credential format and claims query")
        }

        val credentialStructure = credentialStructureExtractor(credential)
        val queryResults = path.query(credentialStructure.jsonElement)
        val result = values?.let { values ->
            queryResults.filter { result ->
                catching {
                    val primitive = result.value.jsonPrimitive
                    values.any { value ->
                        catching {
                            when (value) {
                                is DCQLExpectedClaimValue.BooleanValue -> primitive.boolean == value.boolean
                                is DCQLExpectedClaimValue.IntegerValue -> primitive.long == value.long
                                is DCQLExpectedClaimValue.StringValue -> if (primitive.isString) {
                                    primitive.content == value.string
                                } else false
                            }
                        }.getOrNull() ?: false
                    }
                }.getOrNull() ?: false
            }
        } ?: queryResults

        DCQLClaimsQueryResult.JsonResult(result)
    }
}
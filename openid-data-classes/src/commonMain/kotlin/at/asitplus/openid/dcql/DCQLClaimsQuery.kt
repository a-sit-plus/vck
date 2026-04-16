package at.asitplus.openid.dcql

import at.asitplus.KmmResult
import kotlinx.serialization.Serializable

@Serializable(with = DCQLClaimsQuerySerializer::class)
sealed interface DCQLClaimsQuery {
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

    /**
     * OID4VP 1.0: REQUIRED The value MUST be a non-empty array representing a claims path pointer that specifies the
     * path to a claim within the Credential, as defined in Section 7.
     */
    val path: DCQLClaimsPathPointer

    object SerialNames {
        const val ID = "id"
        const val VALUES = "values"
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
    fun executeClaimsQueryAgainstCredential(
        credentialStructure: DCQLCredentialClaimStructure
    ): KmmResult<DCQLClaimsQueryResult> = when (this) {
        is DCQLAmbiguousClaimsQuery -> executeClaimsQueryAgainstCredential(credentialStructure)

        is DCQLIsoMdocClaimsQuery -> when (credentialStructure) {
            is DCQLCredentialClaimStructure.IsoMdocStructure -> executeClaimsQueryAgainstCredential(
                credentialStructure
            )

            is DCQLCredentialClaimStructure.JsonBasedStructure -> throw IllegalArgumentException(
                "Incompatible credential claim structure: Expected `ISO MDOC` but got `JSON`"
            )
        }

        is DCQLJsonClaimsQuery -> when (credentialStructure) {
            is DCQLCredentialClaimStructure.JsonBasedStructure -> executeClaimsQueryAgainstCredential(
                credentialStructure
            )

            is DCQLCredentialClaimStructure.IsoMdocStructure -> throw IllegalArgumentException(
                "Incompatible credential claim structure: Expected `JSON` but got `ISO MDOC`"
            )
        }
    }
}



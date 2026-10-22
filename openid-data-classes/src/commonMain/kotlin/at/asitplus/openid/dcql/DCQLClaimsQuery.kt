package at.asitplus.openid.dcql

import at.asitplus.KmmResult
import kotlinx.serialization.Serializable

@Serializable(with = DCQLClaimsQuerySerializer::class)
sealed interface DCQLClaimsQuery {
    /**
     * OID4VP 1.0, 6.3: id: REQUIRED if claim_sets is present in the Credential Query; OPTIONAL otherwise. A string
     * identifying the particular claim. The value MUST be a non-empty string consisting of alphanumeric, underscore
     * (_), or hyphen (-) characters. Within the particular claims array, the same id MUST NOT be present more than
     * once.
     */
    val id: DCQLClaimsQueryIdentifier?

    /**
     * OID4VP 1.0, 6.3: values: OPTIONAL A non-empty array of strings, integers or boolean values that specifies the
     * expected values of the claim. If the values property is present, the Wallet SHOULD return the claim only if the
     * type and value of the claim both match exactly for at least one of the elements in the array. Details of the
     * processing rules are defined in Section 6.4.1.
     *
     * If a Wallet implements value matching and the Credential being matched is an ISO mdoc-based credential, the CBOR
     * value used for matching MUST first be converted to JSON, following the advice given in Section 6.1 of [RFC8949].
     * The resulting JSON value is then used to match against the values property as specified above. When conversion
     * according to these rules is not clearly defined, behavior is out of scope of this specification.
     */
    val values: List<DCQLExpectedClaimValue>?

    /**
     * OID4VP 1.0, 6.3: path: REQUIRED The value MUST be a non-empty array representing a claims path pointer that
     * specifies the path to a claim within the Credential, as defined in Section 7.
     */
    val path: DCQLClaimsPathPointer

    object SerialNames {
        const val ID = "id"
        const val VALUES = "values"
        const val PATH = "path"
    }

    /**
     * OpenID4VP 1.0, 6.4.1. Selecting Claims
     *
     * The following rules apply for selecting claims via claims and claim_sets:
     *
     *     If claims is absent, the Verifier is requesting no claims that are selectively disclosable; the Wallet MUST
     *     return only the claims that are mandatory to present (e.g., SD-JWT and Key Binding JWT for a Credential of
     *     format IETF SD-JWT VC).
     *     If claims is present, but claim_sets is absent, the Verifier requests all claims listed in claims.
     *     If both claims and claim_sets are present, the Verifier requests one combination of the claims listed in
     *     claim_sets. The order of the options conveyed in the claim_sets array expresses the Verifier's preference
     *     for what is returned; the Wallet SHOULD return the first option that it can satisfy. If the Wallet cannot
     *     satisfy any of the options, it MUST NOT return any claims.
     *     claim_sets MUST NOT be present if claims is absent.
     *
     * When a Claims Query contains a restriction on the values of a claim, the Wallet SHOULD NOT return the claim if
     * its value does not match according to the rules for values defined in Section 6.3, i.e., the claim should be
     * treated the same as if it did not exist in the Credential. Implementing this restriction may not be possible in
     * all cases, for example, if the Wallet does not have access to the claim value before presentation or user consent
     * or if another component routing the request to the Wallet does not have access to the claim value. It is
     * ultimately up to the Wallet and/or the End-User if the value matching request is followed. Therefore, Verifiers
     * MUST treat restrictions expressed using values as a best-effort way to improve user privacy, but MUST NOT rely
     * on it for security checks.
     *
     * The purpose of the claim_sets syntax is to provide a way for a Verifier to describe alternative ways a given
     * Credential can satisfy the request. The array ordering expresses the Verifier's preference for how to fulfill
     * the request. The first element in the array is the most preferred and the last element in the array is the least
     * preferred. Verifiers SHOULD use the principle of least information disclosure to influence how they order these
     * options. For example, a proof of age request should prioritize requesting an attribute like age_over_18 over an
     * attribute like birth_date. The claim_sets syntax is not intended to define options the End-User can choose from,
     * see Section 6.4.3 for more information. The Wallet is recommended to return the first option it can satisfy since
     * that is the preferred option from the Verifier. However, there can be reasons to deviate. Non-exhaustive examples
     * of such reasons are:
     *
     *     scenarios where the Verifier did not order the options to minimize information disclosure
     *     operational reasons why returning a different option than the first option has UX benefits for the Wallet.
     *
     * If the Wallet cannot deliver all claims requested by the Verifier according to these rules, it MUST NOT return
     * the respective Credential.
     *
     * For Credential Formats that do not support selective disclosure, the case of both claims and claim_sets being
     * absent is interpreted as requesting a presentation of the "full credential" since all claims are mandatory to
     * present.
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

/**
 * OpenID4VP 1.0, 6.3: values: "OPTIONAL A non-empty array of strings, integers or boolean values that specifies the
 * expected values of the claim."
 */
internal fun DCQLClaimsQuery.requireNonEmptyValues() = require(values?.isNotEmpty() != false) {
    "`values` must be a non-empty array if present."
}

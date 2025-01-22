package at.asitplus.openid.dcql

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.CredentialFormatEnum
import kotlinx.serialization.Serializable

@Serializable(with = DCQLCredentialQuerySerializer::class)
sealed interface DCQLCredentialQuery {
    /**
     * OID4VP draft 23: id: REQUIRED. A string identifying the Credential in the response and, if
     * provided, the constraints in credential_sets. The value MUST be a non-empty string
     * consisting of alphanumeric, underscore (_) or hyphen (-) characters. Within the
     * Authorization Request, the same id MUST NOT be present more than once.
     */
    val id: DCQLCredentialQueryIdentifier

    /**
     * OID4VP draft 23: format: REQUIRED. A string that specifies the format of the requested
     * Verifiable Credential. Valid Credential Format Identifier values are defined in Appendix B.
     */
    val format: CredentialFormatEnum

    /**
     * OID4VP draft 23: meta: OPTIONAL. An object defining additional properties requested by the
     * Verifier that apply to the metadata and validity data of the Credential. The properties of
     * this object are defined per Credential Format. Examples of those are in Appendix B.4.3.1 and
     * Appendix B.3.1.1. If omitted, no specific constraints are placed on the metadata or validity
     * of the requested Credential.
     */
    val meta: DCQLCredentialMetadataAndValidityConstraints?

    /**
     * OID4VP draft 23: claims: OPTIONAL. A non-empty array of objects as defined in Section 6.3
     * that specifies claims in the requested Credential.
     *
     * Relevant References:
     * - DCQLClaimQuery: Within the particular claims array, the same id MUST NOT be present more
     *  than once.
     */
    val claims: List<DCQLClaimsQuery>?

    /**
     * OID4VP draft 23: claim_sets: OPTIONAL. A non-empty array containing arrays of identifiers
     * for elements in claims that specifies which combinations of claims for the Credential are
     * requested. The rules for selecting claims to send are defined in Section 6.3.1.1.
     */
    val claimSets: List<List<DCQLClaimsQueryIdentifier>>?


    object SerialNames {
        const val ID = "id"
        const val FORMAT = "format"
        const val META = "meta"
        const val CLAIMS = "claims"
        const val CLAIM_SETS = "claim_sets"
    }


    companion object {
        fun validate(query: DCQLCredentialQuery) = query.run {
            if (claims?.isEmpty() == true) {
                throw IllegalArgumentException("Value of `claims` must not be the empty list.")
            }
            if (claimSets?.isEmpty() == true) {
                throw IllegalArgumentException("Value of `claim_sets` must not be the empty list.")
            }
            if ((claims ?: listOf()).mapNotNull { it.id }.let { it.distinct().size != it.size }) {
                throw IllegalArgumentException("Value of `credentials` contains multiple credential queries with the same id.")
            }
            if (claimSets != null) {
                claims?.forEach {
                    if (it.id == null) {
                        throw IllegalArgumentException("Value for `id` in claims is REQUIRED if claim_sets is present in the Credential Query.")
                    }
                }
            }
        }
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
    fun <Credential : Any> executeCredentialQueryAgainstCredential(
        credential: Credential,
        credentialFormatExtractor: (Credential) -> CredentialFormatEnum,
        mdocCredentialDoctypeExtractor: (Credential) -> String,
        sdJwtCredentialTypeExtractor: (Credential) -> String,
        credentialClaimStructureExtractor: (Credential) -> DCQLCredentialClaimStructure,
    ): KmmResult<DCQLCredentialQueryMatchingResult> = catching {
        if (credentialFormatExtractor(credential) != format) {
            throw IllegalArgumentException("Incompatible credential format")
        }

        val credentialFormatInstance = credentialFormatExtractor(credential)
        when(credentialFormatInstance) {
            CredentialFormatEnum.MSO_MDOC -> {
                val meta = meta as DCQLIsoMdocCredentialMetadataAndValidityConstraints
                if (meta.doctypeValue != null && mdocCredentialDoctypeExtractor(credential) != meta.doctypeValue) {
                    throw IllegalArgumentException("Incompatible MDOC document type")
                }
            }

            CredentialFormatEnum.VC_SD_JWT -> {
                val meta = meta as DCQLSdJwtCredentialMetadataAndValidityConstraints
                val allowedTypes = meta.vctValues
                if (allowedTypes != null && sdJwtCredentialTypeExtractor(credential) !in allowedTypes) {
                    throw IllegalArgumentException("Incompatible SD-JWT credential type")
                }
            }

            else -> {}
        }

        val claimQueries = claims
            ?: return KmmResult.success(DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult)

        val requestedClaimSets = claimSets?.let {
            val claimQueryLookup = claimQueries.associateBy {
                it.id!!
            }
            it.map {
                it.map {
                    claimQueryLookup[it]
                        ?: throw IllegalArgumentException("Claim specified in `claim_sets` was not found in `claims`.")
                }
            }
        } ?: listOf(claimQueries)

        val result = requestedClaimSets.firstNotNullOf { claimQueryCombination ->
            catching {
                claimQueryCombination.map { claimQuery ->
                    claimQuery.executeClaimsQueryAgainstCredential(
                        credentialQuery = this,
                        credential = credential,
                        credentialStructureExtractor = credentialClaimStructureExtractor,
                    ).getOrThrow()
                }
            }.getOrNull()
        }
        DCQLCredentialQueryMatchingResult.ClaimsQueryResults(result)
    }
}
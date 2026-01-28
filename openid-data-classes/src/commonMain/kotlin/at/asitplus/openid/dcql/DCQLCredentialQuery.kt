package at.asitplus.openid.dcql

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications: Added jwt_vc_json DCQL support for Orange implementation
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.data.NonEmptyList
import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.openid.CredentialFormatEnum
import io.github.aakira.napier.Napier
import kotlinx.serialization.Serializable

@Serializable(with = DCQLCredentialQuerySerializer::class)
sealed interface DCQLCredentialQuery {
    /**
     * OID4VP 1.0: id: REQUIRED. A string identifying the Credential in the response and, if
     * provided, the constraints in credential_sets. The value MUST be a non-empty string
     * consisting of alphanumeric, underscore (_) or hyphen (-) characters. Within the
     * Authorization Request, the same id MUST NOT be present more than once.
     */
    val id: DCQLCredentialQueryIdentifier

    /**
     * OID4VP 1.0: format: REQUIRED. A string that specifies the format of the requested
     * Verifiable Credential. Valid Credential Format Identifier values are defined in Appendix B.
     */
    val format: CredentialFormatEnum

    /**
     *  OID4VP 1.0: multiple: OPTIONAL. A boolean which indicates whether multiple Credentials can be returned
     *  for this Credential Query. If omitted, the default value is false.
     */
    val multiple: Boolean?

    /**
     * OID4VP 1.0: meta: REQUIRED. An object defining additional properties requested by the
     * Verifier that apply to the metadata and validity data of the Credential. The properties of
     * this object are defined per Credential Format. Examples of those are in Appendix B.3.5 and
     * Appendix B.2.3. If empty, no specific constraints are placed on the metadata or validity
     * of the requested Credential.
     *
     * Compare: https://github.com/openid/OpenID4VP/issues/590
     */
    val meta: DCQLCredentialMetadataAndValidityConstraints

    /**
     * OID4VP 1.0: trusted_authorities: OPTIONAL. A non-empty array of objects as defined in Section 6.1.1 that
     * specifies expected authorities or trust frameworks that certify Issuers, that the Verifier will accept.
     * Every Credential returned by the Wallet SHOULD match at least one of the conditions present
     * in the corresponding trusted_authorities array if present.
     */
    val trustedAuthorities: NonEmptyList<DCQLTrustedAuthorityQueryEntry>?

    /**
     *  OID4VP: require_cryptographic_holder_binding: OPTIONAL. A boolean which indicates whether the Verifier
     *  requires a Cryptographic Holder Binding proof. The default value is true, i.e., a Verifiable Presentation
     *  with Cryptographic Holder Binding is required. If set to false, the Verifier accepts a Credential without
     *  Cryptographic Holder Binding proof.
     */
    val requireCryptographicHolderBinding: Boolean?

    /**
     * OID4VP 1.0: claims: OPTIONAL. A non-empty array of objects as defined in Section 6.3
     * that specifies claims in the requested Credential. Verifiers MUST NOT point to the same claim more than once
     * in a single query. Wallets SHOULD ignore such duplicate claim queries.
     *
     * Relevant References:
     * - DCQLClaimQuery: Within the particular claims array, the same id MUST NOT be present more
     *  than once.
     */
    val claims: DCQLClaimsQueryList<DCQLClaimsQuery>?

    /**
     * OID4VP 1.0: claim_sets: OPTIONAL. A non-empty array containing arrays of identifiers
     * for elements in [claims] that specifies which combinations of claims for the Credential are
     * requested. The rules for selecting claims to send are defined in Section 6.4.1.
     */
    val claimSets: NonEmptyList<List<DCQLClaimsQueryIdentifier>>?

    companion object {
        operator fun invoke(
            id: DCQLCredentialQueryIdentifier,
            format: CredentialFormatEnum,
            meta: DCQLCredentialMetadataAndValidityConstraints,
            claims: DCQLClaimsQueryList<DCQLClaimsQuery>? = null,
            claimSets: NonEmptyList<List<DCQLClaimsQueryIdentifier>>? = null,
            multiple: Boolean? = false,
            trustedAuthorities: NonEmptyList<DCQLTrustedAuthorityQueryEntry>? = null,
            requireCryptographicHolderBinding: Boolean? = true,
        ): DCQLCredentialQuery = when (format) {
            CredentialFormatEnum.JWT_VC -> DCQLJwtVcCredentialQuery(
                id = id,
                format = format,
                meta = meta as DCQLJwtVcCredentialMetadataAndValidityConstraints,
                claims = claims?.map {
                    it as DCQLJsonClaimsQuery
                }?.toNonEmptyList()?.let(::DCQLClaimsQueryList),
                claimSets = claimSets,
                multiple = multiple,
                trustedAuthorities = trustedAuthorities,
                requireCryptographicHolderBinding = requireCryptographicHolderBinding,
            )

            CredentialFormatEnum.DC_SD_JWT -> DCQLSdJwtCredentialQuery(
                id = id,
                format = format,
                meta = meta as DCQLSdJwtCredentialMetadataAndValidityConstraints,
                claims = claims?.map {
                    it as DCQLJsonClaimsQuery
                }?.toNonEmptyList()?.let(::DCQLClaimsQueryList),
                claimSets = claimSets,
                multiple = multiple,
                trustedAuthorities = trustedAuthorities,
                requireCryptographicHolderBinding = requireCryptographicHolderBinding,
            )

            CredentialFormatEnum.MSO_MDOC -> DCQLIsoMdocCredentialQuery(
                id = id,
                format = format,
                meta = meta as DCQLIsoMdocCredentialMetadataAndValidityConstraints,
                claims = claims?.map {
                    it as DCQLIsoMdocClaimsQuery
                }?.toNonEmptyList()?.let(::DCQLClaimsQueryList),
                claimSets = claimSets,
                multiple = multiple,
                trustedAuthorities = trustedAuthorities,
                requireCryptographicHolderBinding = requireCryptographicHolderBinding,
            )

            else -> throw IllegalArgumentException("Unsupported credential format: ${format}")
        }
    }

    object SerialNames {
        const val ID = "id"
        const val FORMAT = "format"
        const val MULTIPLE = "multiple"
        const val META = "meta"
        const val TRUSTED_AUTHORITIES = "trusted_authorities"
        const val REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING = "require_cryptographic_holder_binding"
        const val CLAIMS = "claims"
        const val CLAIM_SETS = "claim_sets"
    }


    fun validate() {
        if (claimSets != null) {
            claims?.forEach {
                if (it.id == null) {
                    throw IllegalArgumentException("Value of `id` in claims is REQUIRED if claim_sets is present in the Credential Query.")
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
        jwtVcCredentialTypeExtractor: (Credential) -> List<String>,
        credentialClaimStructureExtractor: (Credential) -> DCQLCredentialClaimStructure,
        satisfiesCryptographicHolderBinding: (Credential) -> Boolean,
        authorityKeyIdentifiers: (Credential) -> Collection<DCQLAuthorityKeyIdentifier>,
    ): KmmResult<DCQLCredentialQueryMatchingResult> = catching {
        if (credentialFormatExtractor(credential) != format) {
            throw IllegalArgumentException("Incompatible credential format")
        }

        val isTrustedAuthorityMatching = trustedAuthorities?.any { trustedAuthority ->
            when (trustedAuthority) {
                is DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier -> {
                    val supportedAuthorityKeyIdentifiers = trustedAuthority.values.map {
                        DCQLAuthorityKeyIdentifier(it)
                    }
                    authorityKeyIdentifiers(credential).any {
                        it in supportedAuthorityKeyIdentifiers
                    }
                }

                /**
                 * https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1-3.10:
                 * OPTIONAL: Every Credential returned by the Wallet SHOULD match at least one
                 * -> It's optional anyway, so let's not throw here
                 */
                is DCQLTrustedAuthorityQueryEntryETSITrustedList,
                is DCQLTrustedAuthorityQueryEntryOpenIDFederation -> false
            }
        } ?: true

        if (!isTrustedAuthorityMatching) {
            throw IllegalArgumentException("Credential matches to none of the trusted authorities.")
        }

        if (requireCryptographicHolderBinding == true && !satisfiesCryptographicHolderBinding(credential)) {
            throw IllegalArgumentException("Credential does not satisfy constraint `require_cryptographic_holder_binding`.")
        }


        Procedures.validateCredentialMetadataAndValidityConstraints(
            credential = credential,
            credentialMetadataAndValidityConstraints = meta,
            mdocCredentialDoctypeExtractor = mdocCredentialDoctypeExtractor,
            sdJwtCredentialTypeExtractor = sdJwtCredentialTypeExtractor,
            jwtVcCredentialTypeExtractor = jwtVcCredentialTypeExtractor
        ).getOrThrow()

        val claimQueries = claims
            ?: return KmmResult.success(DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult)

        val requestedClaimsQueryCombinations = claimSets?.let {
            val claimQueryLookup = claimQueries.associateBy {
                it.id
                    ?: throw IllegalArgumentException("Claim query identifier is missing despite the presence of `claim_sets`.")
            }
            it.map {
                it.map {
                    claimQueryLookup[it]
                        ?: throw IllegalArgumentException("Claim specified in `claim_sets` was not found in `claims`.")
                }
            }.toNonEmptyList()
        } ?: nonEmptyListOf(claimQueries)

        val result = requestedClaimsQueryCombinations.firstNotNullOf { claimQueryCombination ->
            catching {
                claimQueryCombination.map { claimQuery ->
                    claimQuery.executeClaimsQueryAgainstCredential(
                        credentialQuery = this,
                        credential = credential,
                        credentialStructureExtractor = credentialClaimStructureExtractor,
                    ).getOrThrow()
                }
            }.onFailure {
                Napier.w("Failed to execute claims query", it)
            }.getOrNull()
        }
        DCQLCredentialQueryMatchingResult.ClaimsQueryResults(result)
    }

    object Procedures {
        fun <Credential : Any> validateCredentialMetadataAndValidityConstraints(
            credential: Credential,
            credentialMetadataAndValidityConstraints: DCQLCredentialMetadataAndValidityConstraints,
            mdocCredentialDoctypeExtractor: (Credential) -> String,
            sdJwtCredentialTypeExtractor: (Credential) -> String,
            jwtVcCredentialTypeExtractor: (Credential) -> List<String>,
        ): KmmResult<Unit> = catching {
            when (credentialMetadataAndValidityConstraints) {
                DCQLEmptyCredentialMetadataAndValidityConstraints -> {
                    // noop
                }

                is DCQLIsoMdocCredentialMetadataAndValidityConstraints -> {
                    credentialMetadataAndValidityConstraints.validate(
                        mdocCredentialDoctypeExtractor(credential)
                    ).getOrThrow()
                }

                is DCQLSdJwtCredentialMetadataAndValidityConstraints -> {
                    credentialMetadataAndValidityConstraints.validate(
                        sdJwtCredentialTypeExtractor(credential)
                    ).getOrThrow()
                }

                is DCQLJwtVcCredentialMetadataAndValidityConstraints -> {
                    credentialMetadataAndValidityConstraints.validate(
                        jwtVcCredentialTypeExtractor(credential)
                    ).getOrThrow()
                }
            }
        }
    }
}

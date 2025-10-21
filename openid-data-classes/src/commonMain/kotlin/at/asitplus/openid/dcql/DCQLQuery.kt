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
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DCQLQuery(
    /**
     * OID4VP 1.0: REQUIRED. A non-empty array of Credential Queries as defined in Section 6.1 that
     * specify the requested credentials.
     */
    @SerialName(SerialNames.CREDENTIALS)
    val credentials: DCQLCredentialQueryList<DCQLCredentialQuery>,

    /**
     * OID4VP 1.0: OPTIONAL. A non-empty array of credential set queries as defined in Section
     * 6.2 that specifies additional constraints on which of the requested Credentials to return.
     */
    @SerialName(SerialNames.CREDENTIAL_SETS)
    val credentialSets: NonEmptyList<DCQLCredentialSetQuery>? = null,
) {
    val requestedCredentialSetQueries: NonEmptyList<DCQLCredentialSetQuery>
        get() = credentialSets ?: nonEmptyListOf(
            DCQLCredentialSetQuery(
                required = true,
                options = nonEmptyListOf(credentials.map { it.id }),
            )
        )

    object SerialNames {
        const val CREDENTIALS = "credentials"
        const val CREDENTIAL_SETS = "credential_sets"
    }

    /**
     *  6.3.1.2. Selecting Credentials
     *
     * The following rules apply for selecting Credentials via credentials and credential_sets:
     * If credential_sets is not provided, the Verifier requests presentations for all Credentials
     * in credentials to be returned.
     *
     * Otherwise, the Verifier requests presentations of Credentials to be returned satisfying
     * all of the Credential Set Queries in the credential_sets array where the required attribute
     * is true or omitted, and
     * optionally, any of the other Credential Set Queries.To satisfy a Credential Set Query, the
     * Wallet MUST return presentations of a set of Credentials that match to one of the options
     * inside the Credential Set Query.Credentials not matching the respective constraints
     * expressed within credentials MUST NOT be returned, i.e., they are treated as if they would
     * not exist in the Wallet.If the Wallet cannot deliver all non-optional Credentials requested
     * by the Verifier according to these rules, it MUST NOT return any Credential(s).
     */
    fun <Credential : Any> execute(
        availableCredentials: List<Credential>,
        credentialFormatExtractor: (Credential) -> CredentialFormatEnum,
        mdocCredentialDoctypeExtractor: (Credential) -> String,
        sdJwtCredentialTypeExtractor: (Credential) -> String,
        jwtVcCredentialTypeExtractor: (Credential) -> List<String>,
        credentialClaimStructureExtractor: (Credential) -> DCQLCredentialClaimStructure,
        satisfiesCryptographicHolderBinding: (Credential) -> Boolean,
        authorityKeyIdentifiers: (Credential) -> List<DCQLAuthorityKeyIdentifier>,
    ): KmmResult<DCQLQueryResult<Credential>> = Procedures.executeQuery(
        credentialQueries = credentials,
        requestedCredentialSetQueries = requestedCredentialSetQueries,
        availableCredentials = availableCredentials,
        credentialFormatExtractor = credentialFormatExtractor,
        mdocCredentialDoctypeExtractor = mdocCredentialDoctypeExtractor,
        sdJwtCredentialTypeExtractor = sdJwtCredentialTypeExtractor,
        jwtVcCredentialTypeExtractor = jwtVcCredentialTypeExtractor,
        credentialClaimStructureExtractor = credentialClaimStructureExtractor,
        satisfiesCryptographicHolderBinding = satisfiesCryptographicHolderBinding,
        authorityKeyIdentifiers = authorityKeyIdentifiers,
    )

    object Procedures {
        /**
         *  6.3.1.2. Selecting Credentials
         *
         * The following rules apply for selecting Credentials via credentials and credential_sets:
         * If credential_sets is not provided, the Verifier requests presentations for all Credentials
         * in credentials to be returned.
         *
         * Otherwise, the Verifier requests presentations of Credentials to be returned satisfying
         * all of the Credential Set Queries in the credential_sets array where the required attribute
         * is true or omitted, and
         * optionally, any of the other Credential Set Queries.To satisfy a Credential Set Query, the
         * Wallet MUST return presentations of a set of Credentials that match to one of the options
         * inside the Credential Set Query.Credentials not matching the respective constraints
         * expressed within credentials MUST NOT be returned, i.e., they are treated as if they would
         * not exist in the Wallet.If the Wallet cannot deliver all non-optional Credentials requested
         * by the Verifier according to these rules, it MUST NOT return any Credential(s).
         */
        fun <Credential : Any> executeQuery(
            credentialQueries: List<DCQLCredentialQuery>,
            requestedCredentialSetQueries: List<DCQLCredentialSetQuery>,
            availableCredentials: List<Credential>,
            credentialFormatExtractor: (Credential) -> CredentialFormatEnum,
            mdocCredentialDoctypeExtractor: (Credential) -> String,
            sdJwtCredentialTypeExtractor: (Credential) -> String,
            jwtVcCredentialTypeExtractor: (Credential) -> List<String>,
            credentialClaimStructureExtractor: (Credential) -> DCQLCredentialClaimStructure,
            satisfiesCryptographicHolderBinding: (Credential) -> Boolean,
            authorityKeyIdentifiers: (Credential) -> List<DCQLAuthorityKeyIdentifier>,
        ): KmmResult<DCQLQueryResult<Credential>> = catching {
            val credentialQueryMatches = findCredentialQueryMatches(
                credentialQueries = credentialQueries,
                availableCredentials = availableCredentials,
                credentialFormatExtractor = credentialFormatExtractor,
                mdocCredentialDoctypeExtractor = mdocCredentialDoctypeExtractor,
                sdJwtCredentialTypeExtractor = sdJwtCredentialTypeExtractor,
                jwtVcCredentialTypeExtractor = jwtVcCredentialTypeExtractor,
                credentialClaimStructureExtractor = credentialClaimStructureExtractor,
                satisfiesCryptographicHolderBinding = satisfiesCryptographicHolderBinding,
                authorityKeyIdentifiers = authorityKeyIdentifiers,
            )

            val satisfiableCredentialSetQueryOptions = findSatisfactoryCredentialSetQueryOptions(
                credentialQueryMatches = credentialQueryMatches,
                requestedCredentialSetQueries = requestedCredentialSetQueries
            ).getOrElse {
                throw IllegalArgumentException("Submission requirements cannot be satisfied.", it)
            }

            DCQLQueryResult(
                credentialQueryMatches = credentialQueryMatches,
                satisfiableCredentialSetQueries = satisfiableCredentialSetQueryOptions
            )
        }

        fun <Credential : Any> findCredentialQueryMatches(
            credentialQueries: List<DCQLCredentialQuery>,
            availableCredentials: List<Credential>,
            credentialFormatExtractor: (Credential) -> CredentialFormatEnum,
            mdocCredentialDoctypeExtractor: (Credential) -> String,
            sdJwtCredentialTypeExtractor: (Credential) -> String,
            jwtVcCredentialTypeExtractor: (Credential) -> List<String>,
            credentialClaimStructureExtractor: (Credential) -> DCQLCredentialClaimStructure,
            satisfiesCryptographicHolderBinding: (Credential) -> Boolean,
            authorityKeyIdentifiers: (Credential) -> List<DCQLAuthorityKeyIdentifier>,
        ): Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<Credential>>> {
            return credentialQueries.associate { credentialQuery ->
                credentialQuery.id to availableCredentials.mapNotNull { credential ->
                    credentialQuery.executeCredentialQueryAgainstCredential(
                        credential = credential,
                        credentialFormatExtractor = credentialFormatExtractor,
                        mdocCredentialDoctypeExtractor = mdocCredentialDoctypeExtractor,
                        sdJwtCredentialTypeExtractor = sdJwtCredentialTypeExtractor,
                        credentialClaimStructureExtractor = credentialClaimStructureExtractor,
                        satisfiesCryptographicHolderBinding = satisfiesCryptographicHolderBinding,
                        authorityKeyIdentifiers = authorityKeyIdentifiers,
                        jwtVcCredentialTypeExtractor = jwtVcCredentialTypeExtractor,
                    ).getOrNull()?.let {
                        DCQLCredentialSubmissionOption(
                            credential = credential,
                            matchingResult = it
                        )
                    }
                }
            }
        }

        fun <Credential : Any> findSatisfactoryCredentialSetQueryOptions(
            credentialQueryMatches: Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<Credential>>>,
            requestedCredentialSetQueries: List<DCQLCredentialSetQuery>,
        ): KmmResult<List<DCQLCredentialSetQuery>> = catching {
            requestedCredentialSetQueries.mapNotNull { credentialSetQuery ->
                catching<DCQLCredentialSetQuery?> {
                    credentialSetQuery.copy(
                        options = credentialSetQuery.options.filter { option ->
                            option.all {
                                credentialQueryMatches[it]?.isNotEmpty() == true
                            }
                        }.toNonEmptyList()
                    )
                }.getOrElse {
                    if (credentialSetQuery.required) {
                        throw IllegalArgumentException("Required credential set query is not satisfiable: $credentialSetQuery", it)
                    }
                    null
                }
            }
        }

        fun isSatisfactoryCredentialSubmission(
            credentialSubmissions: Set<DCQLCredentialQueryIdentifier>,
            requestedCredentialSetQueries: List<DCQLCredentialSetQuery>,
        ): Boolean = requestedCredentialSetQueries.all {
            !it.required || it.options.any {
                credentialSubmissions.containsAll(it)
            }
        }
    }
}


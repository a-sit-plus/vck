package at.asitplus.openid.dcql

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.CredentialFormatEnum
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DCQLQuery(
    /**
     * OID4VP draft 23: REQUIRED. A non-empty array of Credential Queries as defined in Section 6.1 that
     * specify the requested Verifiable Credentials.
     *
     * Relevant references:
     * - DCQLCredentialQuery: Within the Authorization Request, the same id MUST NOT be present
     *  more than once.
     */
    @SerialName(SerialNames.CREDENTIALS)
    val credentials: List<DCQLCredentialQuery>,

    /**
     * OID4VP draft 23: OPTIONAL. A non-empty array of credential set queries as defined in Section
     * 6.2 that specifies additional constraints on which of the requested Verifiable Credentials
     * to return.
     */
    @SerialName(SerialNames.CREDENTIAL_SETS)
    val credentialSets: List<DCQLCredentialSetQuery>?
) {
    init {
        validate(this)
    }

    object SerialNames {
        const val CREDENTIALS = "credentials"
        const val CREDENTIAL_SETS = "credential_sets"
    }

    companion object {
        fun validate(query: DCQLQuery) = query.run {
            if (credentials.isEmpty()) {
                throw IllegalArgumentException("Value of `credentials` must not be the empty list.")
            }
            if (credentialSets?.isEmpty() == true) {
                throw IllegalArgumentException("Value of `credential_sets` must not be empty if it exists.")
            }
            if (credentials.distinctBy { it.id }.size != credentials.size) {
                throw IllegalArgumentException("Value of `credentials` contains multiple credential queries with the same id.")
            }
        }
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
        credentialClaimStructureExtractor: (Credential) -> DCQLCredentialClaimStructure,
    ): KmmResult<DCQLQueryResult<Credential>> = Procedures.executeQuery(
        credentials = credentials,
        requiredCredentialSets = credentialSets ?: listOf(
            DCQLCredentialSetQuery(
                required = true,
                options = listOf(credentials.map { it.id }),
            )
        ),
        availableCredentials = availableCredentials,
        credentialFormatExtractor = credentialFormatExtractor,
        mdocCredentialDoctypeExtractor = mdocCredentialDoctypeExtractor,
        sdJwtCredentialTypeExtractor = sdJwtCredentialTypeExtractor,
        credentialClaimStructureExtractor = credentialClaimStructureExtractor,
    )

    fun <Credential : Any> findCredentialQueryMatches(
        availableCredentials: List<Credential>,
        credentialFormatExtractor: (Credential) -> CredentialFormatEnum,
        mdocCredentialDoctypeExtractor: (Credential) -> String,
        sdJwtCredentialTypeExtractor: (Credential) -> String,
        credentialClaimStructureExtractor: (Credential) -> DCQLCredentialClaimStructure,
    ): Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<Credential>>> =
        Procedures.findCredentialQueryMatches(
            credentialQueries = credentials,
            availableCredentials = availableCredentials,
            credentialFormatExtractor = credentialFormatExtractor,
            mdocCredentialDoctypeExtractor = mdocCredentialDoctypeExtractor,
            sdJwtCredentialTypeExtractor = sdJwtCredentialTypeExtractor,
            credentialClaimStructureExtractor = credentialClaimStructureExtractor,
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
            credentials: List<DCQLCredentialQuery>,
            requiredCredentialSets: List<DCQLCredentialSetQuery>,
            availableCredentials: List<Credential>,
            credentialFormatExtractor: (Credential) -> CredentialFormatEnum,
            mdocCredentialDoctypeExtractor: (Credential) -> String,
            sdJwtCredentialTypeExtractor: (Credential) -> String,
            credentialClaimStructureExtractor: (Credential) -> DCQLCredentialClaimStructure,
        ): KmmResult<DCQLQueryResult<Credential>> = catching {
            val credentialQueryMatches = findCredentialQueryMatches(
                credentials,
                availableCredentials = availableCredentials,
                credentialFormatExtractor = credentialFormatExtractor,
                mdocCredentialDoctypeExtractor = mdocCredentialDoctypeExtractor,
                sdJwtCredentialTypeExtractor = sdJwtCredentialTypeExtractor,
                credentialClaimStructureExtractor = credentialClaimStructureExtractor,
            )

            val satisfiableCredentialSetQueries = findSatisfactoryCredentialSetQueries(
                credentialQueryMatches = credentialQueryMatches,
                request = requiredCredentialSets
            ).getOrThrow()

            DCQLQueryResult(
                credentialQueryMatches = credentialQueryMatches,
                satisfiableCredentialSetQueries = satisfiableCredentialSetQueries
            )
        }

        fun <Credential : Any> findCredentialQueryMatches(
            credentialQueries: List<DCQLCredentialQuery>,
            availableCredentials: List<Credential>,
            credentialFormatExtractor: (Credential) -> CredentialFormatEnum,
            mdocCredentialDoctypeExtractor: (Credential) -> String,
            sdJwtCredentialTypeExtractor: (Credential) -> String,
            credentialClaimStructureExtractor: (Credential) -> DCQLCredentialClaimStructure,
        ): Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<Credential>>> {
            return credentialQueries.associate { credentialQuery ->
                credentialQuery.id to availableCredentials.mapNotNull { credential ->
                    credentialQuery.executeCredentialQueryAgainstCredential(
                        credential = credential,
                        credentialFormatExtractor = credentialFormatExtractor,
                        mdocCredentialDoctypeExtractor = mdocCredentialDoctypeExtractor,
                        sdJwtCredentialTypeExtractor = sdJwtCredentialTypeExtractor,
                        credentialClaimStructureExtractor = credentialClaimStructureExtractor,
                    ).getOrNull()?.let {
                        DCQLCredentialSubmissionOption(
                            credential = credential,
                            matchingResult = it
                        )
                    }
                }
            }
        }

        fun <Credential : Any> findSatisfactoryCredentialSetQueries(
            credentialQueryMatches: Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<Credential>>>,
            request: List<DCQLCredentialSetQuery>,
        ): KmmResult<List<DCQLCredentialSetQuery>> = catching {
            request.map { credentialSetQuery ->
                credentialSetQuery.copy(
                    options = credentialSetQuery.options.filter { option ->
                        option.all {
                            it in credentialQueryMatches
                        }
                    }
                ).also {
                    if (it.required && it.options.isEmpty()) {
                        throw IllegalArgumentException("Presentation requirements cannot be satisfied.")
                    }
                }
            }
        }
    }
}


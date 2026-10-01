package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialSubmissionOption
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLQueryMatchingResult
import io.github.aakira.napier.Napier

/**
 * Holder-facing view of a DCQL match.
 *
 * [dcqlQueryMatchingResult] identifies matches by their index in [credentials]. [credentialQueryMatches] resolves
 * those indices to the actual credentials and retains the matching result that controls which claims are disclosed.
 */
data class HolderDCQLQueryMatchingResult<Credential : Any>(
    val dcqlQueryMatchingResult: DCQLQueryMatchingResult,
    override val credentials: List<Credential>,
) : HolderPresentationRequestMatchingResult<Credential> {
    val credentialQueryMatches = dcqlQueryMatchingResult.credentialQueryMatches.mapValues {
        it.value.map { (index, matching) ->
            DCQLCredentialSubmissionOption(
                credential = credentials[index.toInt()],
                matchingResult = matching,
            )
        }
    }

    /**
     * Builds a valid automatic submission for the required credential sets in [dcqlQuery].
     *
     * For every required set, this selects the first satisfiable option. It then submits the first matching
     * credential per query, or every match when that query allows `multiple`. Optional credential sets are omitted.
     * Wallets that obtain a different choice from the user should build the submission map themselves.
     */
    fun toDefaultSubmission(
        dcqlQuery: DCQLQuery,
    ): KmmResult<Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<Credential>>>> =
        catching {
            val allowsMultiple = dcqlQuery.credentials.filter { it.multiple }.map { it.id }.toSet()
            // submit the first options of the required queries by default
            val queriesToBePresented = dcqlQuery.requestedCredentialSetQueries.filter {
                it.required
            }.map {
                it.options.first {
                    it.all {
                        it in dcqlQueryMatchingResult.credentialQueryMatches
                    }
                }
            }.flatten()

            queriesToBePresented.associateWith { queryId ->
                val matches = credentialQueryMatches[queryId] ?: run {
                    Napier.d("Credential query with identifier is missing: $queryId")
                    throw IllegalStateException("Missing credential query result")
                }

                if (queryId in allowsMultiple) {
                    matches
                } else {
                    matches.take(1)
                }
            }.filterValues {
                it.isNotEmpty()
            }
        }
}

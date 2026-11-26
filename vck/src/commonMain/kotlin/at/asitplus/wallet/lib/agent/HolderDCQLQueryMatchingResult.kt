package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialSubmissionOption
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLQueryMatchingResult

/**
 * Holder-facing view of a DCQL match.
 *
 * [dcqlQueryMatchingResult] identifies matches by their index in [credentials]. [credentialQueryMatches] resolves
 * those indices to the actual credentials and retains the matching result that controls which claims are disclosed,
 * and [credentialSets] shows which credential queries the holder can present together, to build a submission with
 * [toSubmission] or [toDefaultSubmission].
 */
data class HolderDCQLQueryMatchingResult<Credential : Any>(
    val dcqlQueryMatchingResult: DCQLQueryMatchingResult,
    override val credentials: List<Credential>,
    /** The query [dcqlQueryMatchingResult] matches, whose credential sets the submissions follow. */
    val dcqlQuery: DCQLQuery,
) : HolderPresentationRequestMatchingResult<Credential> {
    /** Matching credentials and the claims to disclose, by the credential query they match, in [credentials] order. */
    val credentialQueryMatches = dcqlQueryMatchingResult.credentialQueryMatches.mapValues {
        it.value.map { (index, matching) ->
            DCQLCredentialSubmissionOption(
                credential = credentials[index.toInt()],
                matchingResult = matching,
            )
        }
    }

    /**
     * The credential sets of [dcqlQuery] (OpenID4VP 1.0, 6.2), or one required set of all its credential queries if
     * it has none (6.4.2), each option with whether the holder can satisfy it, i.e. has a matching credential for each
     * of its credential queries. Wallets show these to let the End-User choose an option of a set, which they
     * "typically" do (6.4.3), and whether to present an optional set, then build the submission with [toSubmission].
     */
    val credentialSets: List<HolderCredentialSet> = dcqlQuery.requestedCredentialSetQueries.map { set ->
        HolderCredentialSet(
            required = set.required,
            options = set.options.map { option ->
                HolderCredentialSetOption(
                    credentialQueryIds = option,
                    satisfiable = option.all { credentialQueryMatches[it].orEmpty().isNotEmpty() },
                )
            },
        )
    }

    /**
     * The submission of the option [selection] chooses for each set to present, both taken from [credentialSets]; an
     * optional set without an entry is not presented. For each credential query of the chosen options, this submits
     * its first matching credential, or every match when that query allows `multiple` (OpenID4VP 1.0, 6.1).
     *
     * Fails if [selection] chooses no option of a required set, as every required set has to be satisfied
     * (OpenID4VP 1.0, 6.4.2), or chooses a set or option that is not in [credentialSets], or an option that can not be
     * satisfied.
     */
    fun toSubmission(
        selection: Map<HolderCredentialSet, HolderCredentialSetOption>,
    ): KmmResult<Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<Credential>>>> =
        catching {
            selection.entries.forEach { entry ->
                require(entry.key in credentialSets) { "The credential set ${entry.key} is not one of the query" }
                require(entry.value in entry.key.options) {
                    "The option ${entry.value} is not one of the credential set ${entry.key}"
                }
                require(entry.value.satisfiable) { "The option ${entry.value} can not be satisfied" }
            }
            credentialSets.forEachIndexed { setIndex, set ->
                require(!set.required || set in selection) {
                    "The credential set at $setIndex is required, but no option was chosen"
                }
            }
            val allowsMultiple = dcqlQuery.credentials.filter { it.multiple }.map { it.id }.toSet()
            val chosen = credentialSets.mapNotNull { selection[it] }
            chosen.flatMap { it.credentialQueryIds }.distinct().associateWith { queryId ->
                val matches = credentialQueryMatches[queryId].orEmpty()
                if (queryId in allowsMultiple) matches else matches.take(1)
            }
        }

    /**
     * Builds a valid automatic submission for the required credential sets in [dcqlQuery]: [toSubmission] of the
     * first satisfiable option of each required set, and of no optional set.
     *
     * Fails if no option of a required credential set is satisfiable, i.e. has a matching credential for each of its
     * queries. Wallets that obtain a different choice from the End-User use [credentialSets] and [toSubmission].
     */
    fun toDefaultSubmission(
    ): KmmResult<Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<Credential>>>> =
        catching {
            val selection = credentialSets.filter { it.required }.associateWith { set ->
                set.options.firstOrNull { it.satisfiable }
                    ?: throw IllegalStateException("No option of a required credential set query is satisfiable")
            }
            toSubmission(selection).getOrThrow()
        }

    /** [toDefaultSubmission] for [dcqlQuery] instead of the query this result holds. */
    @Deprecated("The result holds the query it matches", ReplaceWith("toDefaultSubmission()"))
    fun toDefaultSubmission(
        dcqlQuery: DCQLQuery,
    ): KmmResult<Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<Credential>>>> =
        copy(dcqlQuery = dcqlQuery).toDefaultSubmission()
}

/**
 * A credential set of a DCQL query as the holder can satisfy it, see [HolderDCQLQueryMatchingResult.credentialSets].
 */
data class HolderCredentialSet(
    /** Whether the set has to be satisfied; if not, the wallet may present it (OpenID4VP 1.0, 6.4.2). */
    val required: Boolean,
    /** The options of the set, any one of which satisfies it (OpenID4VP 1.0, 6.2). */
    val options: List<HolderCredentialSetOption>,
)

/** An option of a [HolderCredentialSet]: credential queries to present together. */
data class HolderCredentialSetOption(
    val credentialQueryIds: List<DCQLCredentialQueryIdentifier>,
    /** Whether the holder has a matching credential for each of [credentialQueryIds]. */
    val satisfiable: Boolean,
)

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
     * The credential sets of [dcqlQuery] (OpenID4VP 1.0, 6.2), or one required set of all its credential queries if
     * it has none (6.4.2), each option with whether the holder can satisfy it, i.e. has a matching credential for each
     * of its credential queries. Wallets show these to let the End-User choose an option of a set, which they
     * "typically" do (6.4.3), and whether to present an optional set, then build the submission with [toSubmission].
     */
    fun credentialSets(dcqlQuery: DCQLQuery): List<HolderCredentialSet> =
        dcqlQuery.requestedCredentialSetQueries.map { set ->
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
     * The submission of the options [selection] chooses: for each set of [credentialSets], in their order, the index
     * of its chosen option, or `null` to present nothing for an optional set. For each credential query of the chosen
     * options, this submits its first matching credential, or every match when that query allows `multiple`
     * (OpenID4VP 1.0, 6.1).
     *
     * Fails if [selection] does not choose for every set, chooses no option of a required set, as every required set
     * has to be satisfied (OpenID4VP 1.0, 6.4.2), or chooses an option that does not exist or can not be satisfied.
     */
    fun toSubmission(
        dcqlQuery: DCQLQuery,
        selection: List<Int?>,
    ): KmmResult<Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<Credential>>>> =
        catching {
            val sets = credentialSets(dcqlQuery)
            require(selection.size == sets.size) {
                "A selection is required for each of the ${sets.size} credential sets, but got ${selection.size}"
            }
            val chosen = sets.indices.mapNotNull { setIndex ->
                val set = sets[setIndex]
                val optionIndex = selection[setIndex]
                if (optionIndex == null) {
                    require(!set.required) { "The credential set at $setIndex is required, but none was chosen" }
                    return@mapNotNull null
                }
                val option = requireNotNull(set.options.getOrNull(optionIndex)) {
                    "The credential set at $setIndex has no option at $optionIndex"
                }
                require(option.satisfiable) {
                    "The option at $optionIndex of the credential set at $setIndex can not be satisfied"
                }
                option
            }
            val allowsMultiple = dcqlQuery.credentials.filter { it.multiple }.map { it.id }.toSet()
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
        dcqlQuery: DCQLQuery,
    ): KmmResult<Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<Credential>>>> =
        catching {
            val selection = credentialSets(dcqlQuery).map { set ->
                if (!set.required) null
                else set.options.indexOfFirst { it.satisfiable }.takeIf { it >= 0 }
                    ?: throw IllegalStateException("No option of a required credential set query is satisfiable")
            }
            toSubmission(dcqlQuery, selection).getOrThrow()
        }
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

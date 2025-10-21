package at.asitplus.wallet.lib.extensions

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialSubmissionOption
import at.asitplus.openid.dcql.DCQLQueryResult
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import io.github.aakira.napier.Napier

fun DCQLQueryResult<SubjectCredentialStore.StoreEntry>.toDefaultSubmission(
    allowsMultiple: Collection<DCQLCredentialQueryIdentifier>
): KmmResult<Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<SubjectCredentialStore.StoreEntry>>>> =
    catching {
        // submit the first options of the required queries by default
        val queriesToBePresented = satisfiableCredentialSetQueries.filter {
            it.required
        }.map {
            it.options.first()
        }.flatten()

        queriesToBePresented.associateWith { queryId ->
            val matches = credentialQueryMatches[queryId] ?: run {
                Napier.d("Credential query with identifier is missing: $queryId")
                throw IllegalStateException("Missing credential query result")
            }

            if(queryId in allowsMultiple) {
                matches
            } else {
                matches.take(1)
            }
        }.filterValues {
            it.isNotEmpty()
        }
    }
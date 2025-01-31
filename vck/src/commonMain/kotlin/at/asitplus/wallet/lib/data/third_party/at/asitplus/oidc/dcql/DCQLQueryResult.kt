package at.asitplus.wallet.lib.data.third_party.at.asitplus.oidc.dcql

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialSubmissionOption
import at.asitplus.openid.dcql.DCQLQueryResult
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import io.github.aakira.napier.Napier

fun DCQLQueryResult<SubjectCredentialStore.StoreEntry>.toDefaultSubmission(): KmmResult<Map<DCQLCredentialQueryIdentifier, DCQLCredentialSubmissionOption<SubjectCredentialStore.StoreEntry>>> =
    catching {
        // submit the first options of the required queries by default
        val queriesToBePresented = satisfiableCredentialSetQueries.filter {
            it.required
        }.map {
            it.options.first()
        }.flatten()

        queriesToBePresented.associate { queryId ->
            val matches = credentialQueryMatches[queryId] ?: run {
                Napier.d("Credential query with identifier is missing: $queryId")
                throw IllegalStateException("Missing credential query result")
            }
            
            queryId to matches.first()
        }
    }
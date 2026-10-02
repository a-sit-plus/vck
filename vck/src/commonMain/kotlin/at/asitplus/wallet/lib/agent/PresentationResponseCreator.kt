@file:Suppress("DEPRECATION")

package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.DeviceRequest
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult
import at.asitplus.openid.dcql.DCQLIsoMdocZkCredentialQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.procedures.iso.DeviceRetrievalProcedure

/** Resolves and validates holder submissions before creating their format-specific response artifacts. */
internal class PresentationResponseCreator(
    private val verifiablePresentationFactory: VerifiablePresentationFactory,
) {

    suspend fun create(
        request: PresentationRequestParameters,
        credentialPresentation: CredentialPresentation,
        matchDCQLQuery: suspend (DCQLQuery) -> KmmResult<HolderDCQLQueryMatchingResult<StoreEntry>>,
        matchDeviceRequest: suspend (DeviceRequest) -> KmmResult<HolderIsoDeviceRetrievalQueryMatchingResult<StoreEntry>>,
    ): KmmResult<PresentationResponseParameters> = catching {
        when (credentialPresentation) {
            is CredentialPresentation.DCQLPresentation ->
                createDcql(
                    request,
                    credentialPresentation,
                    matchDCQLQuery
                )

            is CredentialPresentation.IsoDeviceRetrievalPresentation ->
                createDeviceResponse(
                    request,
                    credentialPresentation,
                    matchDeviceRequest
                )
        }
    }

    private suspend fun createDcql(
        request: PresentationRequestParameters,
        presentation: CredentialPresentation.DCQLPresentation,
        matchDCQLQuery: suspend (DCQLQuery) -> KmmResult<HolderDCQLQueryMatchingResult<StoreEntry>>,
    ): PresentationResponseParameters.DCQLParameters {
        val dcqlQuery = presentation.presentationRequest.dcqlQuery
        val credentialSubmissions = presentation.credentialQuerySubmissions
            ?: matchDCQLQuery(dcqlQuery).getOrThrow().toDefaultSubmission(dcqlQuery).getOrThrow()

        DCQLQuery.Procedures.checkCredentialSetQueryRequirements(
            credentialSubmissions = credentialSubmissions.keys,
            requestedCredentialSetQueries = dcqlQuery.requestedCredentialSetQueries,
        ).getOrThrow()

        val presentations = credentialSubmissions.mapValues { (queryId, submissions) ->
            val query = dcqlQuery.credentials.first { it.id == queryId }
            if (!query.multiple && submissions.size != 1) {
                throw IllegalArgumentException(
                    "Credential query ${query.id} does not allow multiple submission, but ${submissions.size} were provided."
                )
            }
            submissions.map {
                val credential = it.credential
                if (credential is StoreEntry.Vc && !query.requireCryptographicHolderBinding) {
                    if (it.matchingResult !is DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult) {
                        throw IllegalArgumentException("Credential type only allows disclosure of all attributes.")
                    }
                    CreatePresentationResult.VcJws(credential.vcSerialized)
                } else {
                    verifiablePresentationFactory.createVerifiablePresentation(
                        request = request,
                        credential = credential,
                        disclosedAttributes = it.matchingResult,
                        zkMetadata = when (query) {
                            is DCQLIsoMdocZkCredentialQuery -> ZkMetadata.IsoMdocZk(query.meta.zkSystemType.toZkRequest())
                            else -> null
                        }
                    ).getOrThrow()
                }
            }
        }

        return PresentationResponseParameters.DCQLParameters(presentations)
    }

    private suspend fun createDeviceResponse(
        request: PresentationRequestParameters,
        presentation: CredentialPresentation.IsoDeviceRetrievalPresentation,
        matchDeviceRequest: suspend (DeviceRequest) -> KmmResult<HolderIsoDeviceRetrievalQueryMatchingResult<StoreEntry>>,
    ): PresentationResponseParameters.DeviceRetrievalParameters {
        val deviceRequest = presentation.presentationRequest.deviceRequest
        val submissions = presentation.submissions
            ?: matchDeviceRequest(deviceRequest).getOrThrow().toDefaultSubmission().getOrThrow()
        val selectedCredentials = DeviceRetrievalProcedure.validateSubmission(deviceRequest, submissions).getOrThrow()
        val result = verifiablePresentationFactory.createVerifiablePresentation(
            request = request,
            isoPresentationParameters = selectedCredentials,
        ).getOrThrow()
        return PresentationResponseParameters.DeviceRetrievalParameters(result.deviceResponse)
    }

}

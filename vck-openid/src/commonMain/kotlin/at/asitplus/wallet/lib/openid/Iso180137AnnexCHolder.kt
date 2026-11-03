package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dcapi.EncryptedResponse
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IsoDeviceRetrievalMatchingResult
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import kotlin.jvm.JvmOverloads

/**
 * Handles ISO/IEC 18013-7 Annex C requests received through the W3C Digital Credentials API.
 *
 * This is intentionally separate from [OpenId4VpHolder], because Annex C is not OpenID4VP even when
 * both protocols are transported through the same browser API.
 */
class Iso180137AnnexCHolder @JvmOverloads constructor(
    private val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    private val holder: Holder = HolderAgent(keyMaterial),
) {

    /** Adapts the Annex C device request to the presentation model used by VC-K's credential matcher. */
    fun createPresentationRequest(
        request: RequestParametersFrom.IsoMdocDcApi,
    ): KmmResult<CredentialPresentationRequest.IsoDeviceRetrieval> = catching {
        CredentialPresentationRequest.IsoDeviceRetrieval(
            deviceRequest = request.parameters.isoMdocRequest.deviceRequest,
        )
    }

    /** Matches mdoc credentials, restricted to platform-selected credential IDs when supplied in [request]. */
    suspend fun getMatchingCredentials(
        request: RequestParametersFrom.IsoMdocDcApi,
    ): KmmResult<IsoDeviceRetrievalMatchingResult<SubjectCredentialStore.StoreEntry>> = catching {
        holder.matchPresentationRequestAgainstCredentialStore(
            presentationRequest = createPresentationRequest(request).getOrThrow(),
            filterByIds = request.credentialIds,
        ).getOrThrow() as? IsoDeviceRetrievalMatchingResult<SubjectCredentialStore.StoreEntry>
            ?: throw IllegalStateException("Holder did not match the device request as ISO device retrieval")
    }

    /** Creates and encrypts the selected mdoc device response according to ISO/IEC 18013-7 Annex C. */
    suspend fun finalizeResponse(
        request: RequestParametersFrom.IsoMdocDcApi,
        credentialPresentation: CredentialPresentation.IsoDeviceRetrievalPresentation,
    ): KmmResult<EncryptedResponse> = catching {
        IsoMdocDcapiResponseBuilder.buildEncryptedResponse(
            credentialPresentation = credentialPresentation,
            isoMdocWalletRequest = request,
            holder = holder,
        )
    }
}

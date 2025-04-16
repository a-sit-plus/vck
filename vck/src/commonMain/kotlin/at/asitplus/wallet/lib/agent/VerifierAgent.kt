package at.asitplus.wallet.lib.agent

import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.iso.DeviceResponse
import at.asitplus.wallet.lib.iso.Document
import at.asitplus.wallet.lib.iso.MobileSecurityObject
import at.asitplus.wallet.lib.jws.SdJwtSigned


/**
 * An agent that only implements [Verifier], i.e. it can only verify credentials of other agents.
 */
class VerifierAgent(
    /**
     * The identifier of this verifier, that is expected to be the audience of verifiable presentations.
     * It may be a cryptographic identifier of the key, but can be anything, e.g. a URL.
     */
    private val identifier: String,
    private val validator: Validator = Validator(),
) : Verifier {

    override suspend fun verifyPresentationSdJwt(
        input: SdJwtSigned,
        challenge: String,
        transactionData: Pair<PresentationRequestParameters.Flow, List<TransactionDataBase64Url>>?,
    ): VerifyPresentationResult = runCatching {
        validator.verifyVpSdJwt(input, challenge, identifier, transactionData)
    }.getOrElse {
        VerifyPresentationResult.ValidationError(it)
    }

    override suspend fun verifyPresentationVcJwt(
        input: JwsSigned<VerifiablePresentationJws>,
        challenge: String,
    ): VerifyPresentationResult = runCatching {
        validator.verifyVpJws(input, challenge, identifier)
    }.getOrElse {
        VerifyPresentationResult.ValidationError(it)
    }

    override suspend fun verifyPresentationIsoMdoc(
        input: DeviceResponse,
        challenge: String,
        verifyDocument: (MobileSecurityObject, Document) -> Boolean,
    ): VerifyPresentationResult = runCatching {
        validator.verifyDeviceResponse(input, verifyDocument)
    }.getOrElse {
        VerifyPresentationResult.ValidationError(it)
    }
}

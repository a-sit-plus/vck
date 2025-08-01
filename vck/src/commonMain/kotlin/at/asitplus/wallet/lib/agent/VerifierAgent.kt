package at.asitplus.wallet.lib.agent

import at.asitplus.catchingUnwrapped
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.Document
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
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
    @Deprecated("Use [validatorVcJws], [validatorSdJwt], [validatorMdoc] instead")
    private val validator: Validator = Validator(),
    private val validatorVcJws: ValidatorVcJws = ValidatorVcJws(validator = validator),
    private val validatorSdJwt: ValidatorSdJwt = ValidatorSdJwt(validator = validator),
    private val validatorMdoc: ValidatorMdoc = ValidatorMdoc(validator = validator),
) : Verifier {

    override suspend fun verifyPresentationSdJwt(
        input: SdJwtSigned,
        challenge: String,
        transactionData: Pair<PresentationRequestParameters.Flow, List<TransactionDataBase64Url>>?,
    ): VerifyPresentationResult = catchingUnwrapped {
        validatorSdJwt.verifyVpSdJwt(input, challenge, identifier, transactionData)
    }.getOrElse {
        VerifyPresentationResult.ValidationError(it)
    }

    override suspend fun verifyPresentationVcJwt(
        input: JwsSigned<VerifiablePresentationJws>,
        challenge: String,
    ): VerifyPresentationResult = catchingUnwrapped {
        validatorVcJws.verifyVpJws(input, challenge, identifier)
    }.getOrElse {
        VerifyPresentationResult.ValidationError(it)
    }

    @Deprecated("Use [verifyPresentationIsoMdoc] without `challenge` instead",
        ReplaceWith("verifyPresentationIsoMdoc(input, verifyDocument)"))
    override suspend fun verifyPresentationIsoMdoc(
        input: DeviceResponse,
        challenge: String,
        verifyDocument: suspend (MobileSecurityObject, Document) -> Boolean,
    ): VerifyPresentationResult = catchingUnwrapped {
        validatorMdoc.verifyDeviceResponse(input, verifyDocument)
    }.getOrElse {
        VerifyPresentationResult.ValidationError(it)
    }

    override suspend fun verifyPresentationIsoMdoc(
        input: DeviceResponse,
        verifyDocument: suspend (MobileSecurityObject, Document) -> Boolean,
    ): VerifyPresentationResult = catchingUnwrapped {
        validatorMdoc.verifyDeviceResponse(input, verifyDocument)
    }.getOrElse {
        VerifyPresentationResult.ValidationError(it)
    }
}

package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.Document
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.data.VcJwsVerificationResultWrapper
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
    private val validatorVcJws: ValidatorVcJws = ValidatorVcJws(),
    private val validatorSdJwt: ValidatorSdJwt = ValidatorSdJwt(),
    private val validatorMdoc: ValidatorMdoc = ValidatorMdoc(),
) : Verifier {
    override suspend fun verifyPresentationSdJwt(
        input: SdJwtSigned,
        challenge: String,
        transactionData: List<TransactionDataBase64Url>?,
    ): KmmResult<VerifyPresentationResult.SuccessSdJwt> = validatorSdJwt.verifyVpSdJwt(
        input = input,
        challenge = challenge,
        clientId = identifier,
        transactionData = transactionData,
    )

    override suspend fun verifyPresentationVcJwt(
        input: JwsCompact,
        challenge: String,
    ): KmmResult<VerifyPresentationResult.Success> = validatorVcJws.verifyVpJws(
        input = input,
        challenge = challenge,
        clientId = identifier,
    )

    override suspend fun verifyUnsignedVcJws(
        input: String
    ): KmmResult<VerifyPresentationResult.SuccessUnsignedVcJws> = validatorVcJws.verifyVcJws(
        input = input,
        publicKey = null,
        vpJws = null
    ).map { jws ->
        VerifyPresentationResult.SuccessUnsignedVcJws(
            VcJwsVerificationResultWrapper(
                vcJws = jws.jws,
                freshnessSummary = validatorVcJws.checkCredentialFreshness(jws.jws),
            )
        )
    }

    override suspend fun verifyPresentationIsoMdoc(
        input: DeviceResponse,
        verifyDocument: suspend (MobileSecurityObject, Document) -> Boolean,
    ): KmmResult<VerifyPresentationResult.SuccessIso> = validatorMdoc.verifyDeviceResponse(
        deviceResponse = input,
        verifyDocumentCallback = verifyDocument,
    )
}

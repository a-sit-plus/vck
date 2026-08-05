package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.Document
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.agent.validation.sdJwt.SdJwtInputValidator
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsInputValidator
import at.asitplus.wallet.lib.data.VcJwsVerificationResultWrapper
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.jws.SdJwtSigned
import kotlin.jvm.JvmOverloads


/**
 * An agent that only implements [Verifier], i.e. it can only verify credentials of other agents.
 */
class VerifierAgent @JvmOverloads constructor(
    /**
     * The identifier of this verifier. It is used as the default expected presentation audience when callers do not
     * provide an explicit transport-specific audience to [verifyPresentationSdJwt]. It may be a cryptographic
     * identifier of the key, but can be anything, e.g. a URL.
     */
    private val identifier: String,
    /**
     * Certificates of the issuers we trust, e.g. extracted from an ETSI trust list. When set, credentials whose
     * issuer certificate is not signed by one of these are rejected. When null, issuer signatures are only
     * verified against the key the credential asserts itself, i.e. no trust decision is made.
     *
     * Note that holder signatures, i.e. the presentation itself and its key binding, are self-asserted by
     * design and stay unaffected by this.
     */
    trustedIssuers: TrustedIssuerCertificates? = null,
    private val validatorVcJws: ValidatorVcJws = ValidatorVcJws(
        vcJwsInputValidator = VcJwsInputValidator(verifyJwsObject = issuerJwsVerifier(trustedIssuers)),
    ),
    private val validatorSdJwt: ValidatorSdJwt = ValidatorSdJwt(
        sdJwtInputValidator = SdJwtInputValidator(verifyJwsObject = issuerJwsVerifier(trustedIssuers)),
    ),
    private val validatorMdoc: ValidatorMdoc = ValidatorMdoc(
        verifyCoseSignature = issuerCoseVerifier(trustedIssuers),
    ),
) : Verifier {

    override suspend fun verifyPresentationSdJwt(
        input: SdJwtSigned,
        challenge: String,
        transactionData: List<TransactionDataBase64Url>?,
        requireCryptographicHolderBinding: Boolean,
        audience: String?,
    ): KmmResult<VerifyPresentationResult.SuccessSdJwt> = validatorSdJwt.verifyVpSdJwt(
        input = input,
        challenge = challenge,
        audience = audience ?: identifier,
        transactionData = transactionData,
        requireCryptographicHolderBinding = requireCryptographicHolderBinding,
    )

    override suspend fun verifyPresentationVcJwt(
        input: JwsCompactTyped<VerifiablePresentationJws>,
        challenge: String,
    ): KmmResult<VerifyPresentationResult.Success> = validatorVcJws.verifyVpJws(
        input = input,
        challenge = challenge,
        clientId = identifier,
    )

    override suspend fun verifyUnsignedVcJws(
        input: String
    ): KmmResult<VerifyPresentationResult.SuccessUnsigned> = validatorVcJws.verifyVcJws(
        input = input,
        publicKey = null,
        vpJws = null
    ).map { jws ->
        VerifyPresentationResult.SuccessUnsigned(
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

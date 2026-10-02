package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.protectedHeaders
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpAuthenticationRequestValidator
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRequestData

/**
 * Most signatures of a multisigned request whose identities are validated, as each one may cause the wallet to
 * fetch status lists, see [wrpRequestDataOfSigners].
 */
const val MAX_MULTISIGNED_WRP_SIGNERS = 16

/** Data to validate the access and registration certificates of one signer of a multisigned request. */
data class SignerWrpRequestData(
    /** Position of the signature, see [VerifierSignature.signatureIndex]. */
    val signatureIndex: Int,
    val clientId: String,
    val requestData: KmmResult<WrpRequestData>,
)

/**
 * Data to validate the identity of every authenticated signer in [verifierSignatures], i.e. the result of validating
 * this request, see [AuthorizationRequestValidator].
 *
 * Each signer's access certificate, client identifier and registration certificate are taken from its own protected
 * header only, which its own signature protects, so they are never combined with those of another signer. Signers
 * that are not authenticated are left out: the protected header of a signature that does not verify may have been
 * copied from any other request, including its access and registration certificates.
 *
 * Fails for requests with more than [MAX_MULTISIGNED_WRP_SIGNERS] signatures.
 */
fun RequestParametersFrom.OpenId4VpDcApiMultiSigned.wrpRequestDataOfSigners(
    verifierSignatures: List<VerifierSignature>,
): KmmResult<List<SignerWrpRequestData>> = catching {
    val headers = jwsTyped.jws.protectedHeaders
    require(headers.size <= MAX_MULTISIGNED_WRP_SIGNERS) {
        "Multisigned request has ${headers.size} signatures, at most $MAX_MULTISIGNED_WRP_SIGNERS are validated"
    }
    val dcqlQuery = requireNotNull(parameters.dcqlQuery) { "No DCQL query in request" }
    verifierSignatures.filter { it.authenticated }.map { signature ->
        SignerWrpRequestData(
            signatureIndex = signature.signatureIndex,
            clientId = signature.clientId,
            requestData = catching {
                val header = requireNotNull(headers.getOrNull(signature.signatureIndex)) {
                    "No protected header for signature ${signature.signatureIndex}"
                }
                require(header.clientId == signature.clientId) {
                    "client_id of signature ${signature.signatureIndex} does not match its protected header"
                }
                WrpAuthenticationRequestValidator(
                    clientId = signature.clientId,
                    certificateChain = header.certificateChain,
                    verifierInfo = signature.verifierInfo,
                    dcqlQuery = dcqlQuery,
                    registrationCertificateRequired = false,
                ).getOrThrow()
            },
        )
    }
}

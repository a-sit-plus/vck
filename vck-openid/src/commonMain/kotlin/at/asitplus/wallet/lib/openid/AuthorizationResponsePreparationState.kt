package at.asitplus.wallet.lib.openid

import at.asitplus.data.NonEmptyList
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.VerifierInfo
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.validation.RelyingPartyValidationResult
import at.asitplus.wallet.lib.validation.ValidationReport
import kotlinx.serialization.Serializable

/**
 * Intermediate result class to display information about the authentication process to the user,
 * i.e., to let them make an informed decision.
 */
@Serializable
data class AuthorizationResponsePreparationState(
    val request: RequestParametersFrom<AuthenticationRequestParameters>,
    /** Extracted from [request], probably fetched remotely. */
    val credentialPresentationRequest: CredentialPresentationRequest?,
    /** Extracted from [request], probably fetched remotely. */
    val clientMetadata: RelyingPartyMetadata?,
    /** Extracted from [request], probably fetched remotely. */
    val jsonWebKeys: Collection<JsonWebKey>?,
    val verifierInfo: NonEmptyList<VerifierInfo>?,
    /** Audience of the presentation to create */
    val audience: String,
) {
    val dcApiCallingOrigin: String?
        get() = (request as? RequestParametersFrom.DcApiRequest)?.callingOrigin

    val responseRequiresEncryption: Boolean
        get() = request.parameters.responseMode?.requiresEncryption == true

    /** Whether the authn request arrived encrypted for a key from `wallet_metadata`, see OpenID4VP 1.0, 5.10. */
    val requestWasEncrypted: Boolean
        get() = request.decryptedFrom != null

}

/**
 * The [validationReport] of an authorization request, see [at.asitplus.wallet.lib.validation.RequestObjectChecks],
 * and the [preparationState] to answer it with, also if the request is rejected: either to answer the verifier with
 * an error, or, where the policy of the wallet allows, after the user decided to proceed.
 */
data class AuthorizationRequestValidation(
    val validationReport: ValidationReport,
    val preparationState: AuthorizationResponsePreparationState,
    /**
     * The result of validating the relying party of a request carrying a registration certificate (WRPRC), whose
     * report is the [at.asitplus.wallet.lib.validation.RelyingPartyChecks] child of [validationReport], with the
     * relying party if accepted, and what its WRPRCs say in any case, see
     * [RelyingPartyValidationResult.untrustedRegistrations]. `null` for a request without one.
     */
    val relyingParty: RelyingPartyValidationResult? = null,
) {
    init {
        require(relyingParty == null || relyingParty.report in validationReport.children) {
            "The report of the relying party is a child of the report of the request"
        }
    }
}

/**
 * The [validation] of an authorization request whose relying party may have a registration certificate (WRPRC) whose
 * status is not resolved yet, see [OpenId4VpHolder.startAuthorizationResponsePreparationDeferringStatus]: show
 * [validation] at once, and replace it with the result of [resolveStatus] once that returns. Its
 * [AuthorizationRequestValidation.preparationState] does not depend on the status.
 */
class AuthorizationRequestValidationPendingStatus internal constructor(
    /**
     * The validation with the status of each such WRPRC not resolved yet: recorded as blocked by a
     * [at.asitplus.wallet.lib.validation.StatusPendingException], it does not decide the report until resolved. The
     * complete validation if not [isPending].
     */
    val validation: AuthorizationRequestValidation,
    private val resolve: (suspend () -> AuthorizationRequestValidation)?,
) {
    /** Whether the status of a WRPRC remains to be resolved with [resolveStatus]. */
    val isPending: Boolean
        get() = resolve != null

    /**
     * Retrieves the status lists of the WRPRCs, and returns the complete validation, with the same
     * [AuthorizationRequestValidation.preparationState], or [validation] if not [isPending]. The request is not
     * validated again, so its `wallet_nonce` is not consumed again. Retrieves the status lists again on each call.
     */
    suspend fun resolveStatus(): AuthorizationRequestValidation = resolve?.invoke() ?: validation
}

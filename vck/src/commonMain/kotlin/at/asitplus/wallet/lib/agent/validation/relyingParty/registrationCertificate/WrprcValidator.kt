@file:Suppress("DEPRECATION")

package at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolver
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRegistrationCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRequestData
import at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate.WrpacIdentifier
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.RegistrationPurpose
import at.asitplus.wallet.lib.validation.SignatureCheck
import at.asitplus.wallet.lib.validation.WRPRC_CWT_TYPE
import at.asitplus.wallet.lib.validation.WRPRC_JWT_TYPE
import at.asitplus.wallet.lib.validation.evaluateRegistrationCertificate
import io.github.aakira.napier.Napier
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

/**
 * Class to verify registration certificates
 * Validations:
 *  - Header, payload and signature
 *  - Certificate trust anchors
 *  - Linkage to access certificate
 *  - Token status
 **/
@Deprecated("Validate relying parties with at.asitplus.wallet.lib.validation.RelyingPartyValidator. To be removed in the next major release.")
class WrprcValidator(
    private val clock: Clock = Clock.System,
    private val timeLeeway: Duration = 5.minutes,
    private val maxValidity: Duration = 365.days
) {

    suspend operator fun invoke(
        identifierResult: WrpacIdentifier?,
        validationData: WrpRequestData,
        tokenStatusResolver: TokenStatusResolver,
        certificateTrustAnchors: TrustedCertificates,
    ): KmmResult<WrprcValidationResult> = catching {
        require(validationData.registrationCertificate.isNotEmpty()) {
            "No registration certificates to verify"
        }
        val validationResult = validationData.registrationCertificate.mapValues { (certificate, _) ->
            catching {
                validateWrpRegistrationCertificate(
                    certificate = certificate,
                    certificateTrustAnchors = certificateTrustAnchors,
                    tokenStatusResolver = tokenStatusResolver,
                    identifierResult = identifierResult
                )
            }.onFailure { Napier.w("Unable to validate registration certificate", it) }
        }

        val requestDataValidity = validationData.registrationCertificate.flatMap { (certificate, request) ->
            validateCredentialRequests(certificate, request).toList()
        }

        WrprcValidationResult(
            certificateValidationResults = validationResult,
            requestDataValidationResults = requestDataValidity,
        )
    }

    @Deprecated(
        "Use validateCredentialRequests, which does not fail for all requests if one can not be validated",
        ReplaceWith("validateCredentialRequests(registrationCert, requests)")
    )
    suspend fun validateRequest(
        registrationCert: WrpRegistrationCertificate, requests: List<WrpCredentialRequest>
    ) = validateCredentialRequests(registrationCert, requests).mapValues { it.value.getOrThrow() }

    /**
     * Validates each of [requests] against [registrationCert], a failure marks that request as invalid.
     */
    suspend fun validateCredentialRequests(
        registrationCert: WrpRegistrationCertificate, requests: List<WrpCredentialRequest>
    ): Map<WrpCredentialRequest, KmmResult<RequestDataValidity>> = requests.associateWith { request ->
        WrprcRequestValidator(request = request, payload = registrationCert.payload)
            .map { (_, validity) -> validity }
            .onFailure { Napier.w("Unable to validate $request", it) }
    }

    /**
     * Validates [certificate] with the checks of [at.asitplus.wallet.lib.validation.RelyingPartyValidator], except its
     * status, which is resolved with [tokenStatusResolver]. Fails if its certificate chain is missing or can not be
     * parsed.
     */
    private suspend fun validateWrpRegistrationCertificate(
        certificate: WrpRegistrationCertificate,
        certificateTrustAnchors: TrustedCertificates,
        tokenStatusResolver: TokenStatusResolver,
        identifierResult: WrpacIdentifier?
    ): WrpRegistrationCertificateValidation {
        when (certificate) {
            is WrpRegistrationCertificate.WrpJwtRegistrationCertificate ->
                requireNotNull(certificate.jwsTyped.jws.jwsHeader.certificateChain) { "Certificate chain is empty." }

            is WrpRegistrationCertificate.WrpCwtRegistrationCertificate -> {
                val chain = certificate.cose.protectedHeader.certificateChain
                    ?: certificate.cose.unprotectedHeader?.certificateChain
                    ?: throw IllegalArgumentException("${certificate.cose} has no certificate chain in COSE header.")
                chain.forEach {
                    X509Certificate.decodeFromDerSafe(it).getOrElse { throwable ->
                        throw IllegalArgumentException("Could not parse certificate from euWrprc COSE header", throwable)
                    }
                }
            }
        }
        val evaluation = evaluateRegistrationCertificate(
            certificate = certificate,
            accessIdentifier = identifierResult,
            purpose = RegistrationPurpose.Presentation(emptyList()),
            anchors = certificateTrustAnchors,
            source = "certificateTrustAnchors",
            signatureCheck = SignatureCheck(),
            maxValidity = maxValidity,
            timeScope = TimeScope(clock.now(), timeLeeway),
        )
        val tokenStatus = certificate.payload.status.statusList
            .let { StatusListInfo(it.idx, UniformResourceIdentifier(it.uri)) }
            .loadTokenStatus(tokenStatusResolver)
        return WrpRegistrationCertificateValidation(
            validHeader = evaluation.header == CheckOutcome.Passed,
            validSignature = evaluation.signature == CheckOutcome.Passed,
            validChain = evaluation.trust.outcome == CheckOutcome.Passed,
            validPayload = evaluation.claims == CheckOutcome.Passed && evaluation.timeliness == CheckOutcome.Passed,
            validLinkage = evaluation.linkage == CheckOutcome.Passed,
            validStatusList = tokenStatus.getOrNull()?.isValid == true,
            tokenStatus = tokenStatus,
        )
    }

    private suspend fun StatusListInfo.loadTokenStatus(
        tokenStatusResolver: TokenStatusResolver
    ) = tokenStatusResolver.invoke(this)
        .onFailure { Napier.w("Unable to obtain token status.", it) }
        .onSuccess { if (!it.isValid) Napier.w("Token status is not valid: $it") }

    object Constants {
        const val WRPRC_JWS_HEADER = WRPRC_JWT_TYPE
        const val WRPRC_CWT_HEADER = WRPRC_CWT_TYPE
    }
}

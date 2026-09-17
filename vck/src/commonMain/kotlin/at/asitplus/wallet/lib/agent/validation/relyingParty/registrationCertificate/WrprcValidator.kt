package at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.data.NonEmptyList
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.openid.OpenIdConstants.VerifierInfo.REGISTRATION_CERT_FORMAT
import at.asitplus.openid.VerifierInfo
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JwsTyped
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpChainValidator
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRequestValidationData
import at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate.WrpacIdentifier
import at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate.WrpacValidationResult
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrprcValidator.Constants.WRPRC_JWS_HEADER
import at.asitplus.wallet.lib.agent.validation.toTokenStatusResolver
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.jws.VerifyJwsSignature
import io.github.aakira.napier.Napier
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

fun interface WrprcValidatorFun {
    suspend fun invoke(
        accessCertValidation: WrpacValidationResult,
        validationData: WrpRequestValidationData,
        statusListTokenResolver: StatusListTokenResolver,
        certificateTrustAnchors: List<X509Certificate>,
    ): KmmResult<WrprcValidationResult>
}

/**
 * Class to verify registration certificates
 * Validations:
 *  - Header, payload and signature of VerifierInfo
 *  - Certificate trust anchors
 *  - Linkage to access certificate
 *  - Token status
 **/
class WrprcValidator(
    private val timeLeeway: Duration = 5.minutes, private val maxValidity: Duration = 365.days
) : WrprcValidatorFun {
    val requestValidator = WrprcRequestValidator()

    fun parse(verifierInfo: VerifierInfo) = catching {
        if (!verifierInfo.format.equals(REGISTRATION_CERT_FORMAT, ignoreCase = true)) {
            Napier.w("skipping $this, expected '$REGISTRATION_CERT_FORMAT' but got '${verifierInfo.format}'.")
            return@catching null
        }
        val jwsTyped = catchingUnwrapped {
            JwsCompactTyped<WrpPayload>(verifierInfo.data)
        }.getOrElse {
            Napier.w("$this ($REGISTRATION_CERT_FORMAT) contains invalid JWS data.", throwable = it)
            return@catching null
        }
        jwsTyped
    }.getOrNull()

    override suspend fun invoke(
        accessCertValidation: WrpacValidationResult,
        validationData: WrpRequestValidationData,
        statusListTokenResolver: StatusListTokenResolver,
        certificateTrustAnchors: List<X509Certificate>,
    ) = catching {
        validationData.verifierInfo ?: run {
            throw Throwable("VerifierInfo is null")
        }
        val verifierInfoValidationResult = validateVerifierInfoList(
            validationData.verifierInfo,
            accessCertValidation.identifierResult,
            certificateTrustAnchors,
            statusListTokenResolver
        )

        if(verifierInfoValidationResult.isEmpty())  throw Throwable("VerifierInfoValidationResult empty")

        val requestDataValidity = validateRequest(validationData, verifierInfoValidationResult)

        requestDataValidity ?: run {
            throw Throwable("RequestDataValidationResult is null")
        }

        WrprcValidationResult(verifierInfoValidationResult, requestDataValidity)
    }

    suspend fun validateRequest(
        validationData: WrpRequestValidationData, registrationCertValidation: WrprcVerifierInfoValidationResult
    ) = validationData.request?.let { presentationRequest ->
        requestValidator.invoke(presentationRequest, registrationCertValidation.keys).getOrThrow()
    }

    suspend fun validateVerifierInfoList(
        verifierInfo: NonEmptyList<VerifierInfo>,
        identifierResult: WrpacIdentifier?,
        certificateTrustAnchors: List<X509Certificate>,
        statusListTokenResolver: StatusListTokenResolver,
    ): WrprcVerifierInfoValidationResult = run {
        verifierInfo.mapNotNull {
            val parsed = parse(it) ?: return@mapNotNull null
            it to validateVerifierInfo(
                jwsTyped = parsed,
                identifierResult = identifierResult,
                certificateTrustAnchors = certificateTrustAnchors,
                statusListTokenResolver = statusListTokenResolver
            )
        }.toMap()
    }


    private suspend fun validateVerifierInfo(
        jwsTyped: JwsTyped<JwsCompact, WrpPayload>,
        identifierResult: WrpacIdentifier?,
        certificateTrustAnchors: List<X509Certificate>,
        statusListTokenResolver: StatusListTokenResolver,
    ): VerifierInfoValidationResult = run {
        val certificateChain = jwsTyped.jws.jwsHeader.certificateChain ?: run {
            throw Throwable("Certificate chain is empty.")
        }
        validateHeader(jwsTyped)

        WrpChainValidator().invoke(
            chain = certificateChain, certificateTrustAnchors = certificateTrustAnchors
        ).getOrThrow()

        validateSignature(jwsTyped, certificateChain.leaf)
        validatePayload(jwsTyped)

        val validLinkage = validateWrpIdentifierLinkage(identifierResult = identifierResult, jwsTyped = jwsTyped)

        val validStatusList = validateWrpStatusList(jwsTyped, statusListTokenResolver)

        VerifierInfoValidationResult(
            jwsTyped = jwsTyped,
            validLinkage = validLinkage,
            validStatusList = validStatusList
        )
    }

    private fun validateHeader(jwsTyped: JwsCompactTyped<WrpPayload>) = run {
        if (jwsTyped.jws.jwsHeader.type != WRPRC_JWS_HEADER) {
            throw Throwable("$jwsTyped has invalid typ in JWS header. " + "expected='rc-wrp+jwt', actual='${jwsTyped.jws.jwsHeader.type}'")
        }
        if (jwsTyped.jws.jwsHeader.algorithm != JwsAlgorithm.Signature.ES256) {
            throw Throwable("$jwsTyped has invalid alg in JWS header. " + "expected='${JwsAlgorithm.Signature.ES256}', actual='${jwsTyped.jws.jwsHeader.algorithm}'")
        }
        Napier.d("header checks passed for $jwsTyped.")
        true
    }

    private suspend fun validateSignature(
        jwsTyped: JwsCompactTyped<WrpPayload>, leafCertificate: X509Certificate
    ) = run {
        val jwsAlgorithm = jwsTyped.jws.jwsHeader.algorithm
        if (jwsAlgorithm !is JwsAlgorithm.Signature) {
            throw Throwable("$jwsTyped uses unsupported JWS algorithm.")
        }
        VerifyJwsSignature().invoke(jwsTyped.jws, leafCertificate.decodedPublicKey.getOrThrow()).getOrThrow().also {
            Napier.d("signature validation passed for $jwsTyped.")
        }
        true
    }

    private fun validatePayload(jwsTyped: JwsCompactTyped<WrpPayload>): Boolean {
        val now = Clock.System.now()
        val payload = jwsTyped.payload
        if (payload.name == null) {
            throw Throwable("$jwsTyped is missing required payload claim 'name'.")
        }
        if (payload.srvDescription.isEmpty()) {
            throw Throwable("$jwsTyped is missing required payload claim 'srv_description'")
        }
        if (payload.credentials.isEmpty()) {
            throw Throwable("$jwsTyped is missing required payload claim 'credentials'.")
        }
        val issuedAt = Instant.fromEpochSeconds(payload.iat)

        payload.exp?.let { exp ->
            val expires = Instant.fromEpochSeconds(exp)
            if (expires <= issuedAt) {
                throw Throwable(
                    "$jwsTyped has invalid temporal claims: exp=${expires} <= iat=${issuedAt}."
                )
            }
            if (expires < (now - timeLeeway)) {
                throw Throwable(
                    "$jwsTyped already expired: exp=${expires} <= now=${now}."
                )
            }

            if (expires > (issuedAt + maxValidity)) {
                throw Throwable(
                    "$jwsTyped exceeds maximum validity: exp=${expires} > iat=${issuedAt} + ${maxValidity}."
                )
            }
        }
        Napier.d("payload checks passed for $jwsTyped.")
        return true
    }

    private suspend fun validateWrpStatusList(
        jwsTyped: JwsCompactTyped<WrpPayload>,
        statusListTokenResolver: StatusListTokenResolver,
    ): Boolean {
        jwsTyped.payload.status.statusList.let { statusList ->
            val tokenStatus = statusListTokenResolver.toTokenStatusResolver().invoke(statusList).getOrElse {
                Napier.w("Unable to obtain token status.", it)
                TokenStatus.Invalid
            }
            if (!tokenStatus.isValid) {
                Napier.w("Token status is not valid")
                return false
            }
            return true
        }

    }

    /**
     * Validates the linkage between access certificate and registration certificate.
     * Reference: ETSI TS 119 475 V1.2.1 (S18-S20)
     **/
    private fun validateWrpIdentifierLinkage(
        identifierResult: WrpacIdentifier?, jwsTyped: JwsCompactTyped<WrpPayload>
    ): Boolean {
        if (identifierResult?.identifier != jwsTyped.payload.sub) {
            Napier.w("Identifier not matching sub")
            return false
        }
        return true
    }


    object Constants {
        val WRPRC_JWS_HEADER = "rc-wrp+jwt"
        val WRPRC_CWT_HEADER = "rc-wrp+cwt"
    }
}


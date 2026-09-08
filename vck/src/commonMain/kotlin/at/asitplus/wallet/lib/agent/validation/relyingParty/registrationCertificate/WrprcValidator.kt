package at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate

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
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrprcValidator.Constants.LOG_TAG
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrprcValidator.Constants.WRPRC_JWS_HEADER
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.extensions.toView
import at.asitplus.wallet.lib.jws.VerifyJwsSignature
import io.github.aakira.napier.Napier
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Class to verify a registration certificates validity.
 **/
object WrprcValidator {
    private val timeLeeway: Duration = 5.minutes
    private val MAX_VALIDITY: Duration = 365.days
    val requestValidator = WrprcRequestValidator()

    fun parse(verifierInfo: VerifierInfo): JwsTyped<JwsCompact, WrpPayload>? = run {
        if (!verifierInfo.format.equals(REGISTRATION_CERT_FORMAT, ignoreCase = true)) {
            Napier.w(
                "skipping $this, expected '$REGISTRATION_CERT_FORMAT' but got '${verifierInfo.format}'.", tag = LOG_TAG
            )
            return null
        }
        val jwsTyped = catchingUnwrapped {
            JwsCompactTyped<WrpPayload>(verifierInfo.data)
        }.getOrElse {
            Napier.w("$this ($REGISTRATION_CERT_FORMAT) contains invalid JWS data.", tag = LOG_TAG, throwable = it)
            return null
        }
        jwsTyped
    }

    suspend fun validate(
        accessCertValidation: WrpacValidationResult,
        validationData: WrpRequestValidationData,
        statusListTokenResolver: StatusListTokenResolver,
        certificateTrustAnchors: List<X509Certificate>,
    ): WrprcValidationResult? {
        validationData.verifierInfo ?: run {
            Napier.w("VerifierInfo is null", tag = LOG_TAG)
            return null
        }
        val verifierInfoValidationResult = validateVerifierInfoList(
            validationData.verifierInfo,
            accessCertValidation.identifierResult,
            certificateTrustAnchors,
            statusListTokenResolver
        )
        val requestDataValidity = validateRequest(validationData, verifierInfoValidationResult)

        requestDataValidity ?: run {
            Napier.w("RequestDataValidationResult is null", tag = LOG_TAG)
            return null
        }

        return WrprcValidationResult(verifierInfoValidationResult, requestDataValidity)
    }

    suspend fun validateRequest(
        validationData: WrpRequestValidationData, registrationCertValidation: WrprcVerifierInfoValidationResult
    ) = validationData.request?.let { presentationRequest ->
        requestValidator.requestCheck(presentationRequest, registrationCertValidation.keys).onFailure {
            Napier.e("$it")
        }.getOrNull()
    }

    suspend fun validateVerifierInfoList(
        verifierInfo: NonEmptyList<VerifierInfo>,
        identifierResult: WrpacIdentifier?,
        certificateTrustAnchors: List<X509Certificate>,
        statusListTokenResolver: StatusListTokenResolver,
    ): WrprcVerifierInfoValidationResult = verifierInfo.associateWith {
        validateVerifierInfo(
            verifierInfo = it,
            identifierResult = identifierResult,
            certificateTrustAnchors = certificateTrustAnchors,
            statusListTokenResolver = statusListTokenResolver
        )
    }

    private suspend fun validateVerifierInfo(
        verifierInfo: VerifierInfo,
        identifierResult: WrpacIdentifier?,
        certificateTrustAnchors: List<X509Certificate>,
        statusListTokenResolver: StatusListTokenResolver,
    ): VerifierInfoValidationResult? = parse(verifierInfo)?.let { jwsTyped ->
        val certificateChain = jwsTyped.jws.jwsHeader.certificateChain ?: run {
            Napier.w("Certificate chain is empty.", tag = LOG_TAG)
            return null
        }
        val headerValid = validateHeader(jwsTyped)
        val chainValid = WrpChainValidator.validateChain(
            chain = certificateChain, certificateTrustAnchors = certificateTrustAnchors
        )

        val leafCertificate = certificateChain.leaf

        val signatureValid = validateSignature(jwsTyped, leafCertificate)
        val payloadValid = validatePayload(jwsTyped)

        val linkageValid = validateWrpIdentifierLinkage(identifierResult = identifierResult, jwsTyped = jwsTyped)

        val statusValid = validateWrpStatusList(jwsTyped, statusListTokenResolver)

        VerifierInfoValidationResult(
            jwsTyped = jwsTyped,
            signatureValid = signatureValid,
            chainValid = chainValid,
            linkageValid = linkageValid,
            headerValid = headerValid,
            payloadValid = payloadValid,
            statusValid = statusValid,
        )
    }

    private fun validateHeader(jwsTyped: JwsCompactTyped<WrpPayload>): Boolean {
        if (jwsTyped.jws.jwsHeader.type != WRPRC_JWS_HEADER) {
            Napier.e(
                "$jwsTyped has invalid typ in JWS header. " + "expected='rc-wrp+jwt', actual='${jwsTyped.jws.jwsHeader.type}'",
                tag = LOG_TAG
            )
            return false
        }
        if (jwsTyped.jws.jwsHeader.algorithm != JwsAlgorithm.Signature.ES256) {
            Napier.e(
                "$jwsTyped has invalid alg in JWS header. " + "expected='${JwsAlgorithm.Signature.ES256}', actual='${jwsTyped.jws.jwsHeader.algorithm}'",
                tag = LOG_TAG
            )
            return false
        }
        Napier.d("header checks passed for $jwsTyped.", tag = LOG_TAG)
        return true
    }

    private suspend fun validateSignature(
        jwsTyped: JwsCompactTyped<WrpPayload>, leafCertificate: X509Certificate
    ): Boolean = catchingUnwrapped {
        val jwsAlgorithm = jwsTyped.jws.jwsHeader.algorithm
        if (jwsAlgorithm !is JwsAlgorithm.Signature) {
            Napier.e("$jwsTyped uses unsupported JWS algorithm.", tag = LOG_TAG)
            return@catchingUnwrapped false
        }
        VerifyJwsSignature().invoke(jwsTyped.jws, leafCertificate.decodedPublicKey.getOrThrow()).getOrThrow().also {
            Napier.d("signature validation passed for $jwsTyped.", tag = LOG_TAG)
        }
        true
    }.getOrDefault(false)

    private fun validatePayload(jwsTyped: JwsCompactTyped<WrpPayload>): Boolean {
        val now = Clock.System.now()
        val payload = jwsTyped.payload
        if (payload.name == null) {
            Napier.e("$jwsTyped is missing required payload claim 'name'.", tag = LOG_TAG)
            return false
        }
        if (payload.srvDescription.isEmpty()) {
            Napier.e("$jwsTyped is missing required payload claim 'srv_description'", tag = LOG_TAG)
            return false
        }
        if (payload.credentials.isEmpty()) {
            Napier.e("$jwsTyped is missing required payload claim 'credentials'.", tag = LOG_TAG)
            return false
        }
        val issuedAt = Instant.fromEpochSeconds(payload.iat)

        payload.exp?.let { exp ->
            val expires = Instant.fromEpochSeconds(exp)
            if (expires <= issuedAt) {
                Napier.e(
                    "$jwsTyped has invalid temporal claims: exp=${expires} <= iat=${issuedAt}.", tag = LOG_TAG
                )
                return false
            }
            if (expires < (now - timeLeeway)) {
                Napier.e(
                    "$jwsTyped already expired: exp=${expires} <= now=${now}.", tag = LOG_TAG
                )
                return false
            }

            if (expires > (issuedAt + MAX_VALIDITY)) {
                Napier.e(
                    "$jwsTyped exceeds maximum validity: exp=${expires} > iat=${issuedAt} + ${MAX_VALIDITY}.",
                    tag = LOG_TAG
                )
                return false
            }
        }
        Napier.d("payload checks passed for $jwsTyped.", tag = LOG_TAG)
        return true
    }

    private suspend fun validateWrpStatusList(
        jwsTyped: JwsCompactTyped<WrpPayload>,
        statusListTokenResolver: StatusListTokenResolver,
    ) = catchingUnwrapped {
        jwsTyped.payload.status.statusList.let { statusListDto ->
            val uri = statusListDto.uri
            val idx = statusListDto.idx
            val tokenStatus = statusListTokenResolver(UniformResourceIdentifier(uri)).parsedPayload.getOrNull()?.let {
                val statusList = (it.revocationList as? StatusList)
                statusList?.toView()?.getOrNull(idx.toLong())
            }
            tokenStatus?.isValid ?: false
        }
    }.getOrElse {
        Napier.w("Unable to get status list entry for $jwsTyped", tag = LOG_TAG)
        false
    }

    /**
     * Validates the linkage between access certificate and registration certificate.
     * Reference: ETSI TS 119 475 V1.2.1 (S18-S20)
     **/
    private fun validateWrpIdentifierLinkage(
        identifierResult: WrpacIdentifier?, jwsTyped: JwsCompactTyped<WrpPayload>
    ) = identifierResult?.identifier == jwsTyped.payload.sub


    object Constants {
        val LOG_TAG = "WrprcValidator"
        val WRPRC_JWS_HEADER = "rc-wrp+jwt"
        val WRPRC_CWT_HEADER = "rc-wrp+cwt"
    }
}


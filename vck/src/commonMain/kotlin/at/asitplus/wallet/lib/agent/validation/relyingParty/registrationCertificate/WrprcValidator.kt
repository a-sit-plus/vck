package at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolver
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpChainValidator
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRegistrationCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRequestData
import at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate.WrpacIdentifier
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrprcValidator.Constants.WRPRC_CWT_HEADER
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrprcValidator.Constants.WRPRC_JWS_HEADER
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.jws.VerifyJwsSignature
import io.github.aakira.napier.Napier
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

fun interface WrprcValidatorFun {
    suspend operator fun invoke(
        identifierResult: WrpacIdentifier?,
        validationData: WrpRequestData,
        tokenStatusResolver: TokenStatusResolver,
        certificateTrustAnchors: List<X509Certificate>,
    ): KmmResult<WrprcValidationResult>
}

/**
 * Class to verify registration certificates
 * Validations:
 *  - Header, payload and signature
 *  - Certificate trust anchors
 *  - Linkage to access certificate
 *  - Token status
 **/
class WrprcValidator(
    private val timeLeeway: Duration = 5.minutes, private val maxValidity: Duration = 365.days
) : WrprcValidatorFun {
    val requestValidator = WrprcRequestValidator()
    val chainValidator = WrpChainValidator()


    override suspend fun invoke(
        identifierResult: WrpacIdentifier?,
        validationData: WrpRequestData,
        tokenStatusResolver: TokenStatusResolver,
        certificateTrustAnchors: List<X509Certificate>,
    ) = catching {
        if (validationData.registrationCertificate.isEmpty()) throw Throwable("No registration certificates to verify")
        val validationResult = validationData.registrationCertificate.mapNotNull { (certificate, _) ->
            certificate to validateWrpRegistrationCertificate(
                certificate = certificate,
                certificateTrustAnchors = certificateTrustAnchors,
                tokenStatusResolver = tokenStatusResolver,
                identifierResult = identifierResult
            )
        }.toMap()

        val requestDataValidity = validationData.registrationCertificate.mapNotNull { (certificate, request) ->
            validateRequest(certificate, request).toList()
        }.flatten()


        WrprcValidationResult(validationResult, requestDataValidity)
    }

    suspend fun validateRequest(
        registrationCert: WrpRegistrationCertificate,
        requests: List<WrpCredentialRequest>
    ) = requests.mapNotNull {
        requestValidator.invoke(request = it, payload = registrationCert.payload).getOrThrow()
    }.toMap()


    private suspend fun validateWrpRegistrationCertificate(
        certificate: WrpRegistrationCertificate,
        certificateTrustAnchors: List<X509Certificate>,
        tokenStatusResolver: TokenStatusResolver,
        identifierResult: WrpacIdentifier?
    ) = when (certificate) {
        is WrpRegistrationCertificate.WrpCwtRegistrationCertificate -> validateCose(
            certificate = certificate,
            certificateTrustAnchors = certificateTrustAnchors,
            tokenStatusResolver = tokenStatusResolver,
            identifierResult = identifierResult
        )


        is WrpRegistrationCertificate.WrpJwtRegistrationCertificate -> validateJwt(
            certificate = certificate,
            certificateTrustAnchors = certificateTrustAnchors,
            tokenStatusResolver = tokenStatusResolver,
            identifierResult = identifierResult
        )

    }


    private suspend fun validateCose(
        certificate: WrpRegistrationCertificate.WrpCwtRegistrationCertificate,
        certificateTrustAnchors: List<X509Certificate>,
        tokenStatusResolver: TokenStatusResolver,
        identifierResult: WrpacIdentifier?
    ) = run {
        val cose = certificate.cose
        val validHeader = validateHeader(cose)
        val validSignature = validateSignature(cose)
        val certificateChainBytes = cose.protectedHeader.certificateChain
            ?: cose.unprotectedHeader?.certificateChain
            ?: throw Throwable("$cose has no certificate chain in COSE header.")
        val chain = certificateChainBytes.map {
            X509Certificate.decodeFromDerSafe(it).getOrElse { throwable ->
                throw IllegalArgumentException("Could not parse certificate from euWrprc COSE header", throwable)
            }
        }
        val validChain = chainValidator.invoke(
            chain = chain, certificateTrustAnchors = certificateTrustAnchors
        ).getOrThrow()
        val payload = certificate.payload
        val validPayload = validatePayload(payload)
        val statusList = payload.status.statusList.let {
            StatusListInfo(it.idx, UniformResourceIdentifier(it.uri))
        }
        val validStatusList = validateWrpStatusList(statusList = statusList, tokenStatusResolver = tokenStatusResolver)
        val validLinkage = validateWrpIdentifierLinkage(identifierResult = identifierResult, payload = payload)

        WrpRegistrationCertificateValidation(
            validHeader = validHeader,
            validSignature = validSignature,
            validChain = validChain,
            validPayload = validPayload,
            validLinkage = validLinkage,
            validStatusList = validStatusList
        )
    }


    private suspend fun validateJwt(
        certificate: WrpRegistrationCertificate.WrpJwtRegistrationCertificate,
        identifierResult: WrpacIdentifier?,
        certificateTrustAnchors: List<X509Certificate>,
        tokenStatusResolver: TokenStatusResolver,
    ) = run {
        val jwsTyped = certificate.jwsTyped
        val certificateChain = jwsTyped.jws.jwsHeader.certificateChain ?: run {
            throw Throwable("Certificate chain is empty.")
        }
        val validHeader = validateHeader(jwsTyped)

        val validChain = chainValidator.invoke(
            chain = certificateChain, certificateTrustAnchors = certificateTrustAnchors
        ).getOrThrow()

        val validSignature = validateSignature(jwsTyped, certificateChain.leaf)
        val validPayload = validatePayload(jwsTyped.payload)

        val validLinkage = validateWrpIdentifierLinkage(identifierResult = identifierResult, payload = jwsTyped.payload)
        val statusList = jwsTyped.payload.status.statusList.let {
            StatusListInfo(it.idx, UniformResourceIdentifier(it.uri))
        }
        val validStatusList = validateWrpStatusList(statusList, tokenStatusResolver)

        WrpRegistrationCertificateValidation(
            validHeader = validHeader,
            validSignature = validSignature,
            validChain = validChain,
            validPayload = validPayload,
            validLinkage = validLinkage,
            validStatusList = validStatusList
        )
    }

    private fun validateHeader(jwsTyped: JwsCompactTyped<WrpPayload>) = run {
        if (jwsTyped.jws.jwsHeader.type != WRPRC_JWS_HEADER) {
            throw Throwable("$jwsTyped has invalid typ in JWS header. " + "expected='$WRPRC_JWS_HEADER', actual='${jwsTyped.jws.jwsHeader.type}'")
        }
        if (jwsTyped.jws.jwsHeader.algorithm != JwsAlgorithm.Signature.ES256) {
            throw Throwable("$jwsTyped has invalid alg in JWS header. " + "expected='${JwsAlgorithm.Signature.ES256}', actual='${jwsTyped.jws.jwsHeader.algorithm}'")
        }
        Napier.d("header checks passed for $jwsTyped.")
        true
    }

    private fun validateHeader(cose: CoseSigned<ByteArray>) = run {
        if (cose.protectedHeader.type != WRPRC_CWT_HEADER) {
            throw Throwable("$cose has invalid typ in CWT header. " + "expected='$WRPRC_CWT_HEADER', actual='${cose.protectedHeader.type}'")
        }
        if (cose.protectedHeader.algorithm != CoseAlgorithm.Signature.ES256) {
            throw Throwable("$cose has invalid alg in CWT header. " + "expected='${CoseAlgorithm.Signature.ES256}', actual='${cose.protectedHeader.algorithm}'")
        }
        Napier.d("header checks passed for $cose.")
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

    private suspend fun validateSignature(
        cose: CoseSigned<ByteArray>
    ) = run {
        if (cose.protectedHeader.algorithm !is CoseAlgorithm.Signature) {
            throw Throwable("$cose uses unsupported Cose algorithm.")
        }
        VerifyCoseSignature<ByteArray>().invoke(coseSigned = cose, byteArrayOf(), null).getOrThrow().also {
            Napier.d("signature validation passed for $cose.")
        }
        true
    }

    private fun validatePayload(payload: WrpPayload): Boolean {
        val now = Clock.System.now()
        if (payload.name == null) {
            throw Throwable("$payload is missing required claim 'name'.")
        }
        if (payload.srvDescription.isEmpty()) {
            throw Throwable("$payload is missing required claim 'srv_description'")
        }
        if (payload.credentials.isEmpty()) {
            throw Throwable("$payload is missing required claim 'credentials'.")
        }
        val issuedAt = payload.iat

        payload.exp?.let { exp ->
            val expires = exp
            if (expires <= issuedAt) {
                throw Throwable(
                    "$payload has invalid temporal claims: exp=${expires} <= iat=${issuedAt}."
                )
            }
            if (expires < (now - timeLeeway)) {
                throw Throwable(
                    "$payload already expired: exp=${expires} <= now=${now}."
                )
            }

            if (expires > (issuedAt + maxValidity)) {
                throw Throwable(
                    "$payload exceeds maximum validity: exp=${expires} > iat=${issuedAt} + ${maxValidity}."
                )
            }
        }
        Napier.d("payload checks passed for $payload.")
        return true
    }

    private suspend fun validateWrpStatusList(
        statusList: StatusListInfo,
        tokenStatusResolver: TokenStatusResolver,
    ): Boolean {
        statusList.let { statusList ->
            val tokenStatus = tokenStatusResolver.invoke(statusList).getOrElse {
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
        identifierResult: WrpacIdentifier?, payload: WrpPayload
    ): Boolean {
        if (identifierResult?.identifier != payload.subjectIdentifier) {
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


package at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.etsi.relyingParty.WrpConstants
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.toCoseKey
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
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKey
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.jws.VerifyJwsSignature
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
class WrprcValidator(
    private val timeLeeway: Duration = 5.minutes,
    private val maxValidity: Duration = 365.days
) {

    suspend operator fun invoke(
        identifierResult: WrpacIdentifier?,
        validationData: WrpRequestData,
        tokenStatusResolver: TokenStatusResolver,
        certificateTrustAnchors: List<X509Certificate>,
    ): KmmResult<WrprcValidationResult> = catching {
        require(validationData.registrationCertificate.isNotEmpty()) {
            "No registration certificates to verify"
        }
        val validationResult = validationData.registrationCertificate.mapNotNull { (certificate, _) ->
            certificate to catchingUnwrapped {
                validateWrpRegistrationCertificate(
                    certificate = certificate,
                    certificateTrustAnchors = certificateTrustAnchors,
                    tokenStatusResolver = tokenStatusResolver,
                    identifierResult = identifierResult
                )
            }.getOrNull()
        }.toMap()

        val requestDataValidity = validationData.registrationCertificate.mapNotNull { (certificate, request) ->
            validateRequest(certificate, request).toList()
        }.flatten()


        WrprcValidationResult(validationResult, requestDataValidity)
    }

    suspend fun validateRequest(
        registrationCert: WrpRegistrationCertificate, requests: List<WrpCredentialRequest>
    ) = requests.associate {
        WrprcRequestValidator(request = it, payload = registrationCert.payload).getOrThrow()
    }

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
        val validHeader = catchingUnwrapped { validateHeader(certificate.cose) }.getOrElse { false }
        val certificateChainBytes = certificate.cose.protectedHeader.certificateChain
            ?: certificate.cose.unprotectedHeader?.certificateChain
            ?: throw Throwable("${certificate.cose} has no certificate chain in COSE header.")
        val chain = certificateChainBytes.map {
            X509Certificate.decodeFromDerSafe(it).getOrElse { throwable ->
                throw IllegalArgumentException("Could not parse certificate from euWrprc COSE header", throwable)
            }
        }
        val validChain = WrpChainValidator(chain, certificateTrustAnchors).getOrElse { false }
        val validSignature = catchingUnwrapped { validateSignature(certificate.cose, chain.leaf) }.getOrElse { false }
        val validPayload = catchingUnwrapped { validatePayload(certificate.payload) }.getOrElse { false }
        val statusList = certificate.payload.status.statusList.let {
            StatusListInfo(it.idx, UniformResourceIdentifier(it.uri))
        }
        val validStatusList = validateWrpStatusList(statusList, tokenStatusResolver)
        val validLinkage = validateWrpIdentifierLinkage(identifierResult, certificate.payload)

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
        val certificateChain = requireNotNull(jwsTyped.jws.jwsHeader.certificateChain) {
            "Certificate chain is empty."
        }
        val validHeader = catchingUnwrapped { validateHeader(jwsTyped) }.getOrElse { false }
        val validChain = WrpChainValidator(certificateChain, certificateTrustAnchors).getOrElse { false }
        val validSignature =
            catchingUnwrapped { validateSignature(jwsTyped, certificateChain.leaf) }.getOrElse { false }
        val validPayload = catchingUnwrapped { validatePayload(jwsTyped.payload) }.getOrElse { false }
        val validLinkage = validateWrpIdentifierLinkage(identifierResult, jwsTyped.payload)
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
        require(jwsTyped.jws.jwsHeader.type == WRPRC_JWS_HEADER) {
            "invalid typ in JWS header expected='$WRPRC_JWS_HEADER', actual='${jwsTyped.jws.jwsHeader.type}'"
        }
        require(jwsTyped.jws.jwsHeader.algorithm == JwsAlgorithm.Signature.ES256) {
            "invalid alg in JWS header: expected='${JwsAlgorithm.Signature.ES256}', actual='${jwsTyped.jws.jwsHeader.algorithm}'"
        }
        true
    }

    private fun validateHeader(cose: CoseSigned<ByteArray>) = run {
        require(cose.protectedHeader.type == WRPRC_CWT_HEADER) {
            "invalid typ in CWT header: expected='$WRPRC_CWT_HEADER', actual='${cose.protectedHeader.type}'"
        }
        require(cose.protectedHeader.algorithm == CoseAlgorithm.Signature.ES256) {
            "invalid alg in CWT header: expected='${CoseAlgorithm.Signature.ES256}', actual='${cose.protectedHeader.algorithm}'"
        }
        require(cose.protectedHeader.kid == null && cose.unprotectedHeader?.kid == null) {
            "$cose must not carry a 'kid' header attribute."
        }
        true
    }

    private suspend fun validateSignature(
        jwsTyped: JwsCompactTyped<WrpPayload>, leafCertificate: X509Certificate
    ) = run {
        require(jwsTyped.jws.jwsHeader.algorithm is JwsAlgorithm.Signature) {
            "$jwsTyped uses unsupported JWS algorithm: ${jwsTyped.jws.jwsHeader.algorithm}"
        }
        VerifyJwsSignature().invoke(jwsTyped.jws, leafCertificate.decodedPublicKey.getOrThrow()).getOrThrow()
        true
    }

    private suspend fun validateSignature(
        cose: CoseSigned<ByteArray>, leafCertificate: X509Certificate
    ) = run {
        require(cose.protectedHeader.algorithm is CoseAlgorithm.Signature) {
            "unsupported Cose algorithm: ${cose.protectedHeader.algorithm}"
        }
        val leafKey = leafCertificate.decodedPublicKey.getOrThrow().toCoseKey().getOrThrow()
        VerifyCoseSignatureWithKey<ByteArray>().invoke(cose, leafKey, byteArrayOf(), null).getOrThrow()
        true
    }

    private fun validatePayload(payload: WrpPayload): Boolean {
        val now = Clock.System.now()
        requireNotNull(payload.name) {
            "$payload is missing required claim 'name'."
        }
        require(payload.srvDescription.isNotEmpty()) {
            "$payload is missing required claim 'srv_description'"
        }
        require(payload.credentials.isNotEmpty()) {
            "$payload is missing required claim 'credentials'."
        }
        // EUDI TS5 registers claim paths only. Until value constraints are evaluated,
        // accepting one would turn a value-restricted grant into a path-wide grant.
        require(payload.credentials.none { credential -> credential.claim.any { it.values != null } }) {
            "WRPRC claim values are not supported for authorization."
        }
        // TODO looks like duplicated code
        val issuedAt = payload.iat
        payload.exp?.let { expires ->
            require(expires > issuedAt) {
                "$payload has invalid temporal claims: exp=$expires <= iat=${issuedAt}."
            }
            require(expires >= (now - timeLeeway)) {
                "$payload already expired: exp=$expires <= now=${now}."
            }
            require(expires <= (issuedAt + maxValidity)) {
                "$payload exceeds maximum validity: exp=$expires > iat=${issuedAt} + ${maxValidity}."
            }
        }
        require(payload.policyId.contains(WrpConstants.POLICY_IDENTIFIER)) {
            "$payload is missing required policy identifier ${WrpConstants.POLICY_IDENTIFIER}"
        }
        return true
    }

    private suspend fun validateWrpStatusList(
        statusList: StatusListInfo,
        tokenStatusResolver: TokenStatusResolver,
    ) = if (!statusList.loadTokenStatus(tokenStatusResolver).isValid) {
        Napier.w("Token status is not valid")
        false
    } else true

    private suspend fun StatusListInfo.loadTokenStatus(
        tokenStatusResolver: TokenStatusResolver
    ) = tokenStatusResolver.invoke(this).getOrElse {
        Napier.w("Unable to obtain token status.", it)
        TokenStatus.Invalid
    }

    /**
     * Validates the linkage between access certificate and registration certificate.
     * Reference: ETSI TS 119 475 V1.2.1 (S18-S20)
     **/
    private fun validateWrpIdentifierLinkage(
        identifierResult: WrpacIdentifier?,
        payload: WrpPayload
    ): Boolean = if (identifierResult?.identifier != payload.subjectIdentifier) {
        Napier.w("Identifier not matching sub")
        false
    } else true


    object Constants {
        const val WRPRC_JWS_HEADER = "rc-wrp+jwt"
        const val WRPRC_CWT_HEADER = "rc-wrp+cwt"
    }
}

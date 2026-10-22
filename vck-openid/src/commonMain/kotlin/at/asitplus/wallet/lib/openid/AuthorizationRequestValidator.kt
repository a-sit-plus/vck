package at.asitplus.wallet.lib.openid

import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.iso.sha256
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.ClientIdScheme
import at.asitplus.openid.OpenIdConstants.VerifierInfo.REGISTRATION_CERT_FORMAT
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JWS
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsGeneral
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.typed
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.wallet.lib.agent.VerifySignature
import at.asitplus.wallet.lib.agent.VerifySignatureFun
import at.asitplus.wallet.lib.agent.requireTrustedSigningCertificate
import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidTransactionData
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.utils.MapStore
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.CheckOutcome.*
import at.asitplus.wallet.lib.validation.RelyingPartyValidationResult
import at.asitplus.wallet.lib.validation.RelyingPartyValidator
import at.asitplus.wallet.lib.validation.RequestObjectChecks
import at.asitplus.wallet.lib.validation.SignatureCheck
import at.asitplus.wallet.lib.validation.StatusPolicy
import at.asitplus.wallet.lib.validation.TimelinessException
import at.asitplus.wallet.lib.validation.TrustPolicy
import at.asitplus.wallet.lib.validation.TrustValidation
import at.asitplus.wallet.lib.validation.ValidationDecision
import at.asitplus.wallet.lib.validation.ValidationPolicy
import at.asitplus.wallet.lib.validation.ValidationReport
import at.asitplus.wallet.lib.validation.VerifierAttestationChecks
import at.asitplus.wallet.lib.validation.toOutcome
import io.ktor.http.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

/**
 * Validates an OpenID4VP authorization request as a wallet, reporting every check, see [RequestObjectChecks]: the
 * request object, its client identifier prefix with the signature and trust it establishes, and, if configured, the
 * relying party behind it with its access and registration certificates, see [RelyingPartyValidator].
 */
internal class AuthorizationRequestValidator(
    private val walletNonceMapStore: MapStore<String, String> = DefaultMapStore(),
    private val allowedDcApiOriginSchemes: suspend () -> Set<String>,
    /**
     * Establishes trust in relying parties with the anchors of their access certificates, which sign requests using
     * the client identifier prefixes `x509_hash` and `x509_san_dns`, and validates the registration certificates a
     * request carries, see [RelyingPartyValidator].
     */
    private val relyingPartyValidator: RelyingPartyValidator,
    private val verifySignature: VerifySignatureFun = VerifySignature(),
    private val clock: Clock = Clock.System,
) {
    private val signatureCheck = SignatureCheck(verifySignature)

    /**
     * The checks [validateAuthorizationRequest] has always made: trust is required only if trust anchors are
     * configured, and the request object may be expired.
     */
    private val compatibilityPolicy = ValidationPolicy(
        trust = if (relyingPartyValidator.hasClientIdentifierTrust) TrustPolicy.RequireAuthorizedSigner
        else TrustPolicy.IntegrityOnly,
        status = StatusPolicy.Skip,
        timeLeeway = 300.seconds,
        requireTimeliness = false,
    )

    /**
     * Validates [request] with [validate] under the checks it has always been validated with, failing with the first
     * rejection. Its relying party certificates are not validated, as they never have been.
     */
    @Throws(OAuth2Exception::class, CancellationException::class)
    suspend fun validateAuthorizationRequest(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
    ) {
        val report = validate(request, compatibilityPolicy, validateRelyingParty = false).report
        if (report.decision != ValidationDecision.ACCEPTED)
            throw report.rejection(compatibilityPolicy)
    }

    /**
     * Validates [request] under [policy], and the relying party behind it if the request carries a registration
     * certificate. Consumes its `wallet_nonce`, so a request can only be validated once. The clock is read once, all
     * checks use that time.
     */
    suspend fun validate(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        policy: ValidationPolicy,
    ): RequestValidation = validate(request, policy, validateRelyingParty = true)

    /** The [report] of a request, and the result of validating its [relyingParty], whose report is a child of it. */
    class RequestValidation(
        val report: ValidationReport,
        val relyingParty: RelyingPartyValidationResult?,
    )

    private suspend fun validate(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        policy: ValidationPolicy,
        validateRelyingParty: Boolean,
    ): RequestValidation {
        val timeScope = TimeScope(clock.now(), policy.timeLeeway)
        val prefix = catching { request.evaluatePrefix(policy, timeScope) }.getOrElse {
            PrefixEvaluation(signature = Failed(it), trust = TrustValidation(Blocked()), clientId = Blocked())
        }
        val checks = RequestObjectChecks(
            parsing = catching { request.requireWellFormed() }.toOutcome(),
            signature = prefix.signature,
            trust = prefix.trust,
            timeliness = request.timeliness(timeScope),
            clientId = prefix.clientId,
            walletNonce = request.walletNonce(),
            expectedOrigin = request.expectedOrigin(),
        )
        val relyingParty = if (validateRelyingParty && request.carriesRegistrationCertificate())
            relyingPartyValidator.validate(request, policy)
        else null
        val report = ValidationReport.requestObject(
            checks = checks,
            policy = policy,
            verifierAttestation = prefix.verifierAttestation,
            relyingParty = relyingParty?.report,
            evaluatedAt = timeScope.now,
        )
        return RequestValidation(report, relyingParty)
    }

    /**
     * Whether the request carries a WRPRC in `verifier_info`, which is then validated with the access certificate
     * that signed the request. Relying parties outside of the EUDI Wallet ecosystem carry none.
     */
    private fun RequestParametersFrom<AuthenticationRequestParameters>.carriesRegistrationCertificate() =
        parameters.verifierInfo?.any { it.format.equals(REGISTRATION_CERT_FORMAT, ignoreCase = true) } == true

    /** What the client identifier prefix of a request establishes. */
    private class PrefixEvaluation(
        val signature: CheckOutcome,
        val trust: TrustValidation,
        val clientId: CheckOutcome,
        val verifierAttestation: ValidationReport? = null,
    )

    /**
     * Media type, response type and mode, and the parameters of the Digital Credentials API, but not whether the
     * calling origin is expected, see [expectedOrigin].
     */
    @Throws(OAuth2Exception::class, CancellationException::class)
    private suspend fun RequestParametersFrom<AuthenticationRequestParameters>.requireWellFormed() {
        (this as? Signed)?.jwsTyped?.jws?.requireRequestObjectType()
        parameters.responseType?.let {
            if (!it.contains(OpenIdConstants.VP_TOKEN)) {
                throw InvalidRequest("invalid response_type: $it")
            }
        } ?: throw InvalidRequest("response_type is null")
        parameters.validateTransactionData()
        if (parameters.responseMode.isAnyDcApi()) {
            validateDcApi()
        }
        if (parameters.responseMode.isAnyDirectPost()) {
            parameters.verifyResponseModeDirectPost()
        }
    }

    /**
     * OpenID4VP 1.0 sections 5.1 and 8.5 require non-empty DCQL credential_ids. CSC's conditional omission
     * of this field applies to other transaction protocols, not to an OpenID4VP authorization request.
     */
    private fun AuthenticationRequestParameters.validateTransactionData(): Unit =
        catchingUnwrapped {
            transactionDataDecoded?.let {
                require(it.isNotEmpty()) { "transaction_data must be non-empty" }
                val queryIds = dcqlQuery?.credentials?.map { it.id.string }?.toSet()
                it.forEach { data ->
                    require(data.credentialIds.isNotEmpty()) { "credential_ids must be present and non-empty" }
                    require(queryIds == null || queryIds.containsAll(data.credentialIds)) {
                        "credential_ids references an unknown DCQL query"
                    }
                }
            } ?: Unit
        }.getOrElse { throw InvalidTransactionData("Invalid transaction_data", it) }

    // A client identifier names exactly one prefix, so these are mutually exclusive; whether its relying party is
    // trusted is up to the relying party validator, see RelyingPartyValidator.clientTrust
    private suspend fun RequestParametersFrom<AuthenticationRequestParameters>.evaluatePrefix(
        policy: ValidationPolicy,
        timeScope: TimeScope,
    ): PrefixEvaluation {
        val clientTrust = relyingPartyValidator.clientTrust(this, timeScope.now)
        return when (val prefix = parameters.clientIdSchemeExtracted) {
            ClientIdScheme.X509SanDns, ClientIdScheme.X509Hash -> evaluateX509(prefix, clientTrust.trust)
            is ClientIdScheme.RedirectUri -> PrefixEvaluation(
                signature = (this as? Signed)?.verifiedWithAssertedKey() ?: NotApplicable,
                trust = clientTrust.trust,
                clientId = catching { parameters.verifyRedirectUrl() }.toOutcome(),
            )

            is ClientIdScheme.VerifierAttestation -> evaluateVerifierAttestation(policy, timeScope, clientTrust.trust)
            // `pre-registered`, `openid_federation`, `decentralized_identifier` and anything unrecognised: the source
            // of trust establishes the keys the request is signed with
            else -> PrefixEvaluation(
                signature = (this as? Signed)?.let { signed ->
                    clientTrust.keys?.let {
                        signed.verifiedWith(it, "request object not signed by a key registered for this client_id")
                    } ?: signed.verifiedWithAssertedKey()
                } ?: NotApplicable,
                trust = clientTrust.trust,
                clientId = NotApplicable,
            )
        }
    }

    /**
     * The client identifier is the DNS name in a SAN of the leaf of `x5c`, or the hash of the leaf; the request is
     * signed with the leaf, and the chain leads to a trusted anchor: "The Wallet MUST validate the signature and the
     * trust chain" (OpenID4VP 1.0, 5.9.3).
     */
    private suspend fun RequestParametersFrom<AuthenticationRequestParameters>.evaluateX509(
        prefix: ClientIdScheme,
        trust: TrustValidation,
    ): PrefixEvaluation {
        val signed = this as? Signed
            ?: return PrefixEvaluation(
                signature = Failed(InvalidRequest("x509 client_id_scheme requires a signed request object")),
                trust = TrustValidation(Blocked()),
                clientId = Blocked(),
            )
        val chain = signed.jwsTyped.jws.signatures().first().header.certificateChain
        val leaf = chain?.takeIf { it.isNotEmpty() }?.leaf
            ?: return PrefixEvaluation(
                signature = Failed(
                    InvalidRequest("x509 client_id_scheme requires an x5c certificate chain in the JOSE header")
                ),
                trust = TrustValidation(Blocked()),
                clientId = Blocked(),
            )
        val clientId = catching {
            when (prefix) {
                ClientIdScheme.X509SanDns -> signed.verifyX509SanDns(
                    leaf = leaf,
                    responseModeIsDirectPost = parameters.responseMode.isAnyDirectPost(),
                    responseModeIsDcApi = parameters.responseMode.isAnyDcApi(),
                )

                else -> signed.verifyX509SanHash(leaf)
            }
        }.toOutcome()
        // The checks above only bind the client_id to the certificate, anyone may mint a certificate carrying a
        // foreign DNS name, so the chain has to lead to a trust anchor known out-of-band, see [trust]
        val key = leaf.decodedPublicKey.getOrElse {
            return PrefixEvaluation(
                signature = Failed(InvalidRequest("Could not read key from certificate in x5c", it)),
                trust = trust,
                clientId = clientId,
            )
        }
        return PrefixEvaluation(
            signature = signed.verifiedWith(listOf(key)),
            trust = trust,
            clientId = clientId,
        )
    }

    /**
     * The Client Identifier MUST equal the `sub` of the verifier attestation JWT in the `jwt` JOSE header, the Wallet
     * MUST validate its signature, its issuer MUST be trusted, and the request MUST be signed with the key from its
     * `cnf` claim (OpenID4VP 1.0, 5.9.3, 12).
     */
    private suspend fun RequestParametersFrom<AuthenticationRequestParameters>.evaluateVerifierAttestation(
        policy: ValidationPolicy,
        timeScope: TimeScope,
        trust: TrustValidation,
    ): PrefixEvaluation {
        val signed = this as? Signed
            ?: return PrefixEvaluation(
                signature = Failed(
                    InvalidRequest("verifier_attestation client_id_scheme requires a signed request object")
                ),
                trust = TrustValidation(Blocked()),
                clientId = Blocked(),
            )
        val attestation = (signed.jwsTyped.jws as? JwsCompact)?.jwsHeader?.attestationJwt
            ?: return PrefixEvaluation(
                signature = Failed(
                    InvalidRequest("verifier_attestation client_id_scheme requires a jwt in the JOSE header")
                ),
                trust = TrustValidation(Blocked()),
                clientId = Blocked(),
            )
        val payload = catching { attestation.typed<JsonWebToken, JwsCompact>().payload }
        // A trusted attester key verified the signature, otherwise it is verified with the key it asserts
        val attestationSignature = if (trust.outcome == Passed && attestation.jwsHeader.certificateChain == null) Passed
        else signatureCheck.verify(attestation).outcome
        val clientId = payload.fold(
            onSuccess = {
                if (it.subject == parameters.clientIdWithoutPrefix) Passed
                else Failed(
                    InvalidRequest("client_id ${parameters.clientIdWithoutPrefix} not matching sub ${it.subject}")
                )
            },
            onFailure = { Blocked() },
        )
        val checks = VerifierAttestationChecks(
            parsing = payload.toOutcome(),
            signature = attestationSignature,
            trust = trust,
            timeliness = payload.getOrNull()
                ?.let { timeliness(it.expiration, it.notBefore, "verifier attestation", timeScope) } ?: Blocked(),
            clientId = clientId,
        )
        // ponytail: `redirect_uris` in the attestation is not checked, JsonWebToken does not model that claim
        val confirmedKey = payload.getOrNull()?.confirmationClaim?.jsonWebKey?.toCryptoPublicKey()?.getOrNull()
        return PrefixEvaluation(
            signature = confirmedKey?.let { signed.verifiedWith(listOf(it)) }
                ?: Failed(InvalidRequest("verifier attestation has no key in cnf")),
            trust = trust,
            clientId = clientId,
            verifierAttestation = ValidationReport.verifierAttestation(checks, policy, timeScope.now),
        )
    }

    /** `exp` and `nbf` of a signed request object, if present (RFC 7519, 4.1.4, 4.1.5). */
    private fun RequestParametersFrom<AuthenticationRequestParameters>.timeliness(timeScope: TimeScope): CheckOutcome {
        val payload = (this as? Signed)?.jwsTyped?.jws?.plainPayload ?: return Passed
        val claims = catching { Json.parseToJsonElement(payload.decodeToString()).jsonObject }
            .getOrElse { return Failed(InvalidRequest("Request object payload is not a JSON object", it)) }
        return timeliness(claims.instant("exp"), claims.instant("nbf"), "request object", timeScope)
    }

    private fun timeliness(expiration: Instant?, notBefore: Instant?, name: String, timeScope: TimeScope) =
        with(timeScope) {
            when {
                expiration != null && expiration.isTooEarly() ->
                    Failed(TimelinessException("The $name is expired", now, notBefore, expiration))

                notBefore != null && notBefore.isTooLate() ->
                    Failed(TimelinessException("The $name is not yet valid", now, notBefore, expiration))

                else -> Passed
            }
        }

    private fun JsonObject.instant(claim: String): Instant? =
        get(claim)?.jsonPrimitive?.longOrNull?.let { Instant.fromEpochSeconds(it) }

    /** The `wallet_nonce` of a request object the wallet fetched has to be the one the wallet sent. */
    private suspend fun RequestParametersFrom<AuthenticationRequestParameters>.walletNonce(): CheckOutcome {
        if (!isFromRequestObject()) return NotApplicable
        val walletNonce = parameters.walletNonce ?: return NotApplicable
        return if (walletNonceMapStore.remove(walletNonce) == walletNonce) Passed
        else Failed(InvalidRequest("wallet_nonce from request not known to us: $walletNonce"))
    }

    /**
     * The calling origin of a signed request over the Digital Credentials API has to be one of its
     * `expected_origins` (OpenID4VP 1.0, A.2).
     */
    private fun RequestParametersFrom<AuthenticationRequestParameters>.expectedOrigin(): CheckOutcome {
        if (!parameters.responseMode.isAnyDcApi()) return NotApplicable
        if (this !is RequestParametersFrom.OpenId4VpDcApiSigned &&
            this !is RequestParametersFrom.OpenId4VpDcApiMultiSigned
        ) return NotApplicable
        val callingOrigin = (this as RequestParametersFrom.DcApiRequest).callingOrigin
        return if (parameters.verifyExpectedOrigin(callingOrigin)) Passed
        else Failed(InvalidRequest("calling origin '$callingOrigin' does not match expected_origins"))
    }

    /** One signature verifies with one of [keys]; for a multi-signed DC API request, one of them suffices. */
    private suspend fun Signed.verifiedWith(
        keys: Collection<CryptoPublicKey>,
        message: String = "Request object signature not verified",
    ): CheckOutcome = catching {
        val verified = jwsTyped.jws.signatures().any { signature ->
            val algorithm = signature.header.algorithm as? JwsAlgorithm.Signature
            algorithm != null && keys.any {
                verifySignature(signature.input, signature.value, algorithm.algorithm, it).isSuccess
            }
        }
        if (!verified) throw InvalidRequest(message)
    }.toOutcome()

    /** With the key the request asserts itself, i.e. the leaf of `x5c`, a `jwk`, or a `did:key` in `kid`. */
    private suspend fun Signed.verifiedWithAssertedKey(): CheckOutcome = when (val jws = jwsTyped.jws) {
        is JwsCompact -> signatureCheck.verify(jws).outcome
        else -> {
            val keys = catching { jws.signatures() }.getOrElse { return Failed(it) }.mapNotNull {
                it.header.certificateChain?.firstOrNull()?.decodedPublicKey?.getOrNull()
                    ?: it.header.jsonWebKey?.toCryptoPublicKey()?.getOrNull()
            }
            if (keys.isEmpty()) Failed(InvalidRequest("No key to verify the request object signature with"))
            else verifiedWith(keys)
        }
    }

    /** One signature of a request object. */
    private class RequestSignature(val header: JwsHeader, val input: ByteArray, val value: CryptoSignature)

    @Throws(OAuth2Exception::class)
    private fun JWS.signatures(): List<RequestSignature> = when (this) {
        is JwsCompact -> listOf(RequestSignature(jwsHeader, signatureInput, signature))
        is JwsGeneral ->
            jwsHeaders.indices.map { RequestSignature(jwsHeaders[it], signatureInputs[it], signatures[it]) }

        else -> throw InvalidRequest("Unsupported request object signature: $this")
    }

    private suspend fun RequestParametersFrom<AuthenticationRequestParameters>.validateDcApi() {
        val dcApiRequest = this as? RequestParametersFrom.DcApiRequest
            ?: throw InvalidRequest("DC API request not set even though response mode is ${parameters.responseMode}")
        val allowedSchemes = allowedDcApiOriginSchemes()
        if (!dcApiRequest.callingOrigin.usesAllowedOriginScheme(allowedSchemes)) {
            throw InvalidRequest("calling origin uses a disallowed scheme")
        }
        when (this) {
            is RequestParametersFrom.OpenId4VpDcApiSigned,
            is RequestParametersFrom.OpenId4VpDcApiMultiSigned,
                -> {
                if (this.parameters.clientId == null)
                    throw InvalidRequest("client_id must be set for signed DC API request")
                val expectedOrigins = this.parameters.expectedOrigins
                if (expectedOrigins.isNullOrEmpty())
                    throw InvalidRequest("expected_origins must be set and non-empty for signed DC API request")
                if (expectedOrigins.any { !it.usesAllowedOriginScheme(allowedSchemes) })
                    throw InvalidRequest("expected_origins contains an origin with a disallowed scheme")
            }

            is RequestParametersFrom.OpenId4VpDcApiUnsigned -> {
                // Nothing to validate: the Wallet authenticates the client through the platform-provided calling origin,
                // and any client_id present in an unsigned request is ignored (not used for authentication).
            }

            else -> throw InvalidRequest("DC API request not set even though response mode is ${parameters.responseMode}")
        }
    }

    /**
     * Entries are serialized scheme names such as `https`, or a more specific platform-origin
     * prefix such as `android:apk-key-hash`. The trailing colon is supplied by this check.
     */
    private fun String.usesAllowedOriginScheme(allowedSchemes: Set<String>): Boolean =
        allowedSchemes.any { allowedScheme ->
            allowedScheme.isNotEmpty() && startsWith("$allowedScheme:")
        }

    private fun RequestParametersFrom<AuthenticationRequestParameters>.isFromRequestObject(): Boolean =
        this is RequestParametersFrom.Json || this is RequestParametersFrom.Jws

    private fun AuthenticationRequestParameters.verifyRedirectUrl() {
        if (redirectUrl != null) {
            if (clientIdWithoutPrefix != redirectUrl) {
                throw InvalidRequest("client_id $clientIdWithoutPrefix not matching redirect_uri $redirectUrl")
            }
        }
    }

    private fun RequestParametersFrom.RequestParametersSigned<AuthenticationRequestParameters>.verifyX509SanDns(
        leaf: X509Certificate,
        responseModeIsDirectPost: Boolean,
        responseModeIsDcApi: Boolean,
    ) {
        if (leaf.tbsCertificate.extensions == null || leaf.tbsCertificate.extensions!!.isEmpty()) {
            throw InvalidRequest("no extensions in x5c")
        }
        val dnsNames = leaf.tbsCertificate.subjectAlternativeNames?.dnsNames
            ?: throw InvalidRequest("no dnsNames in x5c")
        if (!dnsNames.contains(parameters.clientIdWithoutPrefix)) {
            throw InvalidRequest("client_id not in dnsNames in x5c $dnsNames")
        }
        if (!responseModeIsDirectPost && !responseModeIsDcApi) {
            val parsedUrl = parameters.redirectUrl?.let { Url(it) }
                ?: throw InvalidRequest("redirect_uri is null")
            //TODO  If the Wallet can establish trust in the Client Identifier authenticated through the
            // certificate it may allow the client to freely choose the redirect_uri value
            if (parsedUrl.host != parameters.clientIdWithoutPrefix) {
                throw InvalidRequest("client_id not in redirect_uri $parsedUrl")
            }
        }
    }

    private fun RequestParametersFrom.RequestParametersSigned<AuthenticationRequestParameters>.verifyX509SanHash(
        leaf: X509Certificate,
    ) {
        val expectedHash = parameters.clientIdWithoutPrefix
        val calculatedHash = leaf.encodeToDerSafe()
            .getOrElse { throw InvalidRequest("Could not encode certificate to DER", it) }
            .sha256().encodeToString(Base64UrlStrict)
        if (calculatedHash != expectedHash) {
            throw InvalidRequest("hash of certificate (${calculatedHash}) is not equal to client_id")
        }
    }

    private fun OpenIdConstants.ResponseMode?.isAnyDcApi() =
        (this == OpenIdConstants.ResponseMode.DcApi) || (this == OpenIdConstants.ResponseMode.DcApiJwt)

    private fun OpenIdConstants.ResponseMode?.isAnyDirectPost() =
        (this == OpenIdConstants.ResponseMode.DirectPost) || (this == OpenIdConstants.ResponseMode.DirectPostJwt)

    private fun AuthenticationRequestParameters.verifyResponseModeDirectPost() {
        if (redirectUrl != null) {
            throw InvalidRequest("redirect_uri is set, but response_mode is $responseMode")
        }
        if (responseUrl == null) {
            // TODO Verify according to rules of redirect_uri from section 5.10 (this is defined in 7.2)
            throw InvalidRequest("response_url is null, but response_mode is $responseMode")
        }
    }
}

private typealias Signed = RequestParametersFrom.RequestParametersSigned<AuthenticationRequestParameters>

/**
 * Why a request object report is rejected under [policy]: the cause of the first check that does not pass, as an
 * [OAuth2Exception]. A failed check is preferred over a blocked one, which is only blocked by another one.
 */
private fun ValidationReport.rejection(policy: ValidationPolicy): OAuth2Exception {
    val checks = checks as RequestObjectChecks
    val trustRequired = policy.trust == TrustPolicy.RequireAuthorizedSigner
    val trustApplies = !(checks.signature == NotApplicable && checks.trust.outcome == NotApplicable)
    val outcomes = buildList {
        add(checks.parsing)
        add(checks.expectedOrigin)
        add(checks.clientId)
        if (trustRequired && trustApplies) add(checks.trust.outcome)
        add(checks.signature)
        add(checks.walletNonce)
        if (policy.requireTimeliness) add(checks.timeliness)
        children.map { it.checks }.filterIsInstance<VerifierAttestationChecks>().forEach {
            add(it.parsing)
            add(it.signature)
            if (trustRequired) add(it.trust.outcome)
            if (policy.requireTimeliness) add(it.timeliness)
            add(it.clientId)
        }
    }
    val cause = outcomes.filterIsInstance<Failed>().firstOrNull()?.throwable
        ?: outcomes.filterIsInstance<Blocked>().firstOrNull()?.cause
        ?: return InvalidRequest("request not accepted")
    return cause as? OAuth2Exception ?: InvalidRequest(cause.message, cause)
}

/**
 * Require `typ` to be `oauth-authz-req+jwt` per OpenID4VP 1.0, 5.
 *
 * A request carrying several signatures, i.e. a multi-signed DC API request per OpenID4VP 1.0, A.3.2.2, is still one
 * request object, so every protected header has to declare it.
 */
@Throws(OAuth2Exception::class)
internal fun JWS.requireRequestObjectType() = when (this) {
    is JwsCompact -> listOf(jwsHeader)
    is JwsGeneral -> jwsHeaders
    else -> throw InvalidRequest("Unsupported request object signature: $this")
}.forEach {
    if (it.type != JwsContentTypeConstants.OAUTH_AUTHZ_REQUEST)
        throw InvalidRequest("request object typ is not ${JwsContentTypeConstants.OAUTH_AUTHZ_REQUEST}: ${it.type}")
}

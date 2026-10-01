package at.asitplus.wallet.lib.openid

import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.iso.sha256
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.ClientIdScheme
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JWS
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsGeneral
import at.asitplus.signum.indispensable.josef.typed
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.wallet.lib.agent.VerifySignature
import at.asitplus.wallet.lib.agent.VerifySignatureFun
import at.asitplus.wallet.lib.agent.requireTrustedSigningCertificate
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.VerifyJwsObjectTrusted
import at.asitplus.wallet.lib.jws.VerifyJwsObjectTrustedCertificate
import at.asitplus.wallet.lib.jws.VerifyJwsSignature
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureFun
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.utils.MapStore
import io.ktor.http.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString

internal class AuthorizationRequestValidator(
    private val walletNonceMapStore: MapStore<String, String> = DefaultMapStore(),
    private val allowedDcApiOriginSchemes: suspend () -> Set<String>,
    /** How to establish trust in the relying party, see [RelyingPartyTrust]. Trust is not evaluated when null. */
    private val relyingPartyTrust: Set<RelyingPartyTrust>? = null,
    private val verifySignature: VerifySignatureFun = VerifySignature(),
    private val verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(verifySignature),
) {
    suspend fun validateAuthorizationRequest(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
    ) {
        (request as? RequestParametersFrom.RequestParametersSigned<AuthenticationRequestParameters>)
            ?.jwsTyped?.jws?.requireRequestObjectType()

        request.parameters.responseType?.let {
            if (!it.contains(OpenIdConstants.VP_TOKEN)) {
                throw InvalidRequest("invalid response_type: $it")
            }
        } ?: throw InvalidRequest("response_type is null")

        if (request.parameters.responseMode.isAnyDcApi()) {
            request.validateDcApi()
        }
        val clientIdScheme = request.parameters.clientIdSchemeExtracted
        if (request.parameters.responseMode.isAnyDirectPost()) {
            request.parameters.verifyResponseModeDirectPost()
        }
        // A client identifier names exactly one scheme, so these are mutually exclusive
        when {
            clientIdScheme.isAnyX509() -> request.verifyClientIdSchemeX509()
            clientIdScheme is ClientIdScheme.RedirectUri -> request.parameters.verifyRedirectUrl()
            clientIdScheme is ClientIdScheme.VerifierAttestation -> request.verifyClientIdSchemeVerifierAttestation()
            clientIdScheme is ClientIdScheme.PreRegistered -> request.verifyClientIdSchemePreRegistered()
            // No client_id at all, e.g. an unsigned DC API request authenticated by its calling origin
            clientIdScheme == null -> Unit
            // `entity_id`, `did` and anything unrecognised, which we cannot evaluate ourselves, so a custom
            // source is the only way to establish trust and the request is rejected without one
            else -> relyingPartyTrust?.requireTrustedBy<RelyingPartyTrust.Custom>(
                configured = "custom trust source for client identifier scheme ${clientIdScheme.stringRepresentation}"
            ) { it.evaluate(request) }
        }
        if (request.isFromRequestObject()) {
            request.parameters.walletNonce?.let {
                if (walletNonceMapStore.remove(it) != it) {
                    throw InvalidRequest("wallet_nonce from request not known to us: $it")
                }
            }
        }
    }

    /**
     * Verifies the signature on a signed request object against [publicKey], which the caller has established as
     * belonging to the relying party named in the `client_id`.
     *
     * For a request carrying several signatures, i.e. a multi-signed DC API request, one of them has to be the
     * relying party's.
     */
    private suspend fun RequestParametersFrom.RequestParametersSigned<AuthenticationRequestParameters>.verifyRequestObjectSignature(
        publicKey: CryptoPublicKey,
    ) {
        val verified = when (val jws = jwsTyped.jws) {
            is JwsCompact -> verifyJwsSignature(jws, publicKey).isSuccess

            is JwsGeneral -> jws.jwsHeaders.indices.any { index ->
                (jws.jwsHeaders[index].algorithm as? JwsAlgorithm.Signature)?.let { algorithm ->
                    verifySignature(
                        jws.signatureInputs[index], jws.signatures[index], algorithm.algorithm, publicKey
                    ).isSuccess
                } == true
            }

            else -> throw InvalidRequest("Unsupported request object signature: $jws")
        }
        if (!verified) {
            throw InvalidRequest("Request object signature not verified")
        }
    }

    /**
     * The Client Identifier MUST equal the `sub` of the verifier attestation JWT, which MUST be issued by a party
     * we trust and be transported in the `jwt` JOSE header, and the request MUST be signed with the key from its
     * `cnf` claim. See [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).
     */
    private suspend fun RequestParametersFrom<AuthenticationRequestParameters>.verifyClientIdSchemeVerifierAttestation() {
        val signedRequest = this as? RequestParametersFrom.RequestParametersSigned<AuthenticationRequestParameters>
            ?: throw InvalidRequest("verifier_attestation client_id_scheme requires a signed request object")
        val attestation = (signedRequest.jwsTyped.jws as? JwsCompact)?.jwsHeader?.attestationJwt
            ?: throw InvalidRequest("verifier_attestation client_id_scheme requires a jwt in the JOSE header")

        val attesterNotTrusted = "verifier attestation not issued by a trusted party"
        if (attestation.jwsHeader.certificateChain != null) {
            relyingPartyTrust?.requireTrustedBy<RelyingPartyTrust.VerifierAttesterCertificates>(
                configured = "trusted verifier attester certificates",
                rejected = attesterNotTrusted,
            ) { source ->
                VerifyJwsObjectTrustedCertificate(
                    verifyJwsSignature = verifyJwsSignature,
                    trustedIssuers = source.certificates,
                )(attestation).getOrThrow()
            }
        } else {
            relyingPartyTrust?.requireTrustedBy<RelyingPartyTrust.VerifierAttesterKeys>(
                configured = "trusted verifier attester keys",
                rejected = attesterNotTrusted,
            ) { source ->
                VerifyJwsObjectTrusted(verifyJwsSignature) { source.keys() }(attestation).getOrThrow()
            }
        }

        val attestationPayload: JsonWebToken = attestation.typed<JsonWebToken, JwsCompact>().payload
        if (attestationPayload.subject != parameters.clientIdWithoutPrefix) {
            throw InvalidRequest(
                "client_id ${parameters.clientIdWithoutPrefix} not matching sub ${attestationPayload.subject}"
            )
        }
        // ponytail: `redirect_uris` in the attestation is not checked, JsonWebToken does not model that claim
        val confirmedKey = attestationPayload.confirmationClaim?.jsonWebKey?.toCryptoPublicKey()?.getOrNull()
            ?: throw InvalidRequest("verifier attestation has no key in cnf")
        signedRequest.verifyRequestObjectSignature(confirmedKey)
    }

    /**
     * The Client Identifier needs to be known to the wallet in advance, so it is looked up in every configured
     * [RelyingPartyTrust.PreRegisteredClients], and a signed request has to be signed by one of the keys
     * registered for it.
     */
    private suspend fun RequestParametersFrom<AuthenticationRequestParameters>.verifyClientIdSchemePreRegistered() {
        val trust = relyingPartyTrust ?: return
        // The wallet authenticates an unsigned DC API client through the platform-provided calling origin, and any
        // client_id it carries is ignored, so there is nothing to look up, see validateDcApi
        if (this is RequestParametersFrom.OpenId4VpDcApiUnsigned) return
        val clientId = parameters.clientIdWithoutPrefix
            ?: throw InvalidRequest("client_id is null")
        val signedRequest = this as? RequestParametersFrom.RequestParametersSigned<AuthenticationRequestParameters>

        trust.requireTrustedBy<RelyingPartyTrust.PreRegisteredClients>(
            configured = "pre-registered relying parties",
            rejected = "client_id $clientId is not a pre-registered relying party",
        ) { source ->
            val registeredKeys = source.lookup(clientId)?.takeIf { it.isNotEmpty() }
                ?: throw IllegalArgumentException("client_id unknown to this source")
            // an unsigned request from a known client identifier, nothing to verify against
            if (signedRequest != null && registeredKeys.none { key ->
                    key.toCryptoPublicKey().getOrNull()
                        ?.let { catching { signedRequest.verifyRequestObjectSignature(it) }.isSuccess } == true
                }) {
                throw IllegalArgumentException("request object not signed by a key registered for this client_id")
            }
        }
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
                if (!this.parameters.verifyExpectedOrigin(dcApiRequest.callingOrigin))
                    throw InvalidRequest(
                        "calling origin '${dcApiRequest.callingOrigin}' does not match expected_origins"
                    )
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

    private fun ClientIdScheme?.isAnyX509() =
        (this == ClientIdScheme.X509SanDns) || (this == ClientIdScheme.X509Hash)

    private suspend fun RequestParametersFrom<AuthenticationRequestParameters>.verifyClientIdSchemeX509() {
        val signedRequest = this as? RequestParametersFrom.RequestParametersSigned<AuthenticationRequestParameters>
            ?: throw InvalidRequest("x509 client_id_scheme requires a signed request object")

        val certChain = when (val jws = signedRequest.jwsTyped.jws) {
            is JwsCompact -> jws.jwsHeader.certificateChain
            is JwsGeneral -> jws.signatureElements.firstOrNull()?.jwsHeader?.certificateChain
            else -> null
        }
        val leaf = certChain
            ?.takeIf { it.isNotEmpty() }
            ?.leaf
            ?: throw InvalidRequest("x509 client_id_scheme requires an x5c certificate chain in the JOSE header")

        when (val clientIdScheme = parameters.clientIdSchemeExtracted) {
            ClientIdScheme.X509SanDns -> signedRequest.verifyX509SanDns(
                leaf = leaf,
                responseModeIsDirectPost = parameters.responseMode.isAnyDirectPost(),
                responseModeIsDcApi = parameters.responseMode.isAnyDcApi(),
            )

            ClientIdScheme.X509Hash -> signedRequest.verifyX509SanHash(leaf)
            // checked before calling this method
            else -> throw InvalidRequest("Unexpected clientIdScheme $clientIdScheme")
        }
        // The checks above only bind the client_id to the certificate, anyone may mint a certificate carrying a
        // foreign DNS name, so the chain has to lead to a trust anchor known out-of-band
        relyingPartyTrust?.requireTrustedBy<RelyingPartyTrust.Certificates>("trusted relying party certificates") {
            certChain.requireTrustedSigningCertificate(it.certificates)
        }
        signedRequest.verifyRequestObjectSignature(leaf.decodedPublicKey.getOrElse {
            throw InvalidRequest("Could not read key from certificate in x5c", it)
        })
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

/**
 * Requires at least one configured trust source of type [T] to establish trust, i.e. to have [check] succeed:
 * The configured sources are a union, so any one of them accepting the relying party is enough.
 *
 * Sources are consulted in order and the first one to accept wins, so the remaining ones are not consulted at
 * all: They may fetch a trust list or hit a database, and once trust is established there is nothing left to ask.
 *
 * Throws when no source of type [T] is configured at all, naming [configured], since configuring trust at all
 * means it has to be established and there is no material to do that with. Throws [rejected] when every source
 * rejected, reporting why each one did: [check] throws to reject.
 */
@Throws(OAuth2Exception::class)
private inline fun <reified T : RelyingPartyTrust> Set<RelyingPartyTrust>.requireTrustedBy(
    configured: String,
    rejected: String = "not trusted by any configured $configured",
    check: (T) -> Unit,
) {
    val sources = filterIsInstance<T>().ifEmpty { throw InvalidRequest("no $configured configured") }
    val failures = mutableListOf<Throwable>()
    for (source in sources) {
        failures += catchingUnwrapped { check(source) }.exceptionOrNull() ?: return
    }
    throw InvalidRequest("$rejected: ${failures.joinToString { it.message ?: it::class.simpleName ?: "" }}")
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

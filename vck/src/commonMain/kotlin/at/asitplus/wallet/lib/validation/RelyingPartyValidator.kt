package at.asitplus.wallet.lib.validation

import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.SessionTranscript
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants.ClientIdScheme
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsGeneral
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.agent.validation.relyingParty.InvalidRegistrationCertificateException
import at.asitplus.wallet.lib.agent.validation.relyingParty.MissingRegistrationCertificateException
import at.asitplus.wallet.lib.agent.validation.relyingParty.ReaderAuthenticationVerifier
import at.asitplus.wallet.lib.agent.validation.relyingParty.UnsupportedWrpRequestException
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRegistrationCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate.WrpacIdentifier
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrpCredentialRequest
import at.asitplus.wallet.lib.validation.CheckOutcome.*
import kotlinx.serialization.decodeFromByteArray
import kotlin.jvm.JvmOverloads
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

/**
 * Validates the wallet-relying party behind a request, as a wallet: its access certificate (WRPAC), which has
 * signed the request, and every registration certificate (WRPRC) in it, with the credentials it requests.
 *
 * Replaces `WrpAuthenticationRequestValidator`, `WrpacValidator`, and `WrprcValidator` with one report.
 */
class RelyingPartyValidator @JvmOverloads constructor(
    /** The sources of trust in relying parties. A source that is not configured blocks trust for what it covers. */
    private val trust: RelyingPartyTrustAnchors = RelyingPartyTrustAnchors(),
    /** Resolves and validates the status of WRPRCs. Without a resolver, their status is blocked. */
    private val statusValidator: StatusValidator = StatusValidator(),
    private val signatureCheck: SignatureCheck = SignatureCheck(),
    /** A WRPRC expires not later than 12 months after its issuance (ETSI TS 119 475 V1.2.1, GEN-5.2.4-08). */
    private val maxRegistrationValidity: Duration = 365.days,
    private val clock: Clock = Clock.System,
) {

    /**
     * Validates the relying party of the signed OpenID4VP [request] under [policy]: the request is signed with the
     * WRPAC in its `x5c`, and carries one WRPRC in `verifier_info` for its DCQL query. The clock is read once, all
     * checks use that time.
     *
     * An ISO mdoc request over the Digital Credentials API needs its session transcript, see the overload [validate].
     */
    suspend fun validate(
        request: RequestParametersFrom<*>,
        policy: ValidationPolicy,
    ): RelyingPartyValidationResult = when (request) {
        is RequestParametersFrom.Jws<*> -> extractSigned(
            jws = request.jws as? JwsCompact,
            parameters = request.parameters as? AuthenticationRequestParameters,
        )

        is RequestParametersFrom.OpenId4VpDcApiSigned -> extractSigned(
            jws = request.jwsTyped.jws,
            parameters = request.parameters
        )

        is RequestParametersFrom.IsoMdocDcApi ->
            unsupported("The session transcript is required for ISO mdoc reader authentication")

        else -> unsigned("The request is not signed by a wallet-relying party")
    }.let { validate(it, policy) }

    /**
     * Validates the relying party of the ISO mdoc [request] under [policy]: every document request is
     * authenticated by one WRPAC over [sessionTranscript] (ISO/IEC 18013-5:2021, 9.1.4), and carries the WRPRC for
     * it in `euWrprc`. The clock is read once, all checks use that time.
     */
    suspend fun validate(
        request: RequestParametersFrom.IsoMdocDcApi,
        sessionTranscript: SessionTranscript,
        policy: ValidationPolicy,
    ): RelyingPartyValidationResult =
        validate(request.parameters.isoMdocRequest.deviceRequest, sessionTranscript, policy)

    /**
     * Validates the relying party of the ISO mdoc [deviceRequest] under [policy], e.g. of a proximity presentation
     * over BLE or NFC: every document request is authenticated by one WRPAC over [sessionTranscript] (ISO/IEC
     * 18013-5:2021, 9.1.4), and carries the WRPRC for it in `euWrprc`. The clock is read once, all checks use that
     * time.
     *
     * Reader authentication is optional (9.1.4): a request without any is reported as unsigned, like an unsigned
     * authorization request, with the `signature` of the WRPAC not applicable and `requestData` failing with an
     * [UnsupportedWrpRequestException], so that a wallet can tell an unauthenticated reader from one whose reader
     * authentication does not verify, whose `signature` fails.
     */
    suspend fun validate(
        deviceRequest: DeviceRequest,
        sessionTranscript: SessionTranscript,
        policy: ValidationPolicy,
    ): RelyingPartyValidationResult = validate(extractMdoc(deviceRequest, sessionTranscript), policy)

    /**
     * Whether trust in the client identifier of a request can be decided for any client identifier prefix, see
     * [clientTrust].
     */
    val hasClientIdentifierTrust: Boolean
        get() = trust.coversClientIdentifiers

    /**
     * Whether the relying party of [request] is trusted for its client identifier prefix at [at], as a wallet must
     * establish before answering (OpenID4VP 1.0, 5.9.3), from the source in [RelyingPartyTrustAnchors] that covers
     * the prefix. Only trust, the signature of the request and the binding of the client identifier are validated
     * by the caller, e.g. with the [ClientTrust.keys].
     */
    suspend fun clientTrust(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        at: Instant,
    ): ClientTrust {
        val signed = request as? RequestParametersFrom.RequestParametersSigned<AuthenticationRequestParameters>
        return when (val prefix = request.parameters.clientIdSchemeExtracted) {
            ClientIdScheme.X509SanDns, ClientIdScheme.X509Hash -> ClientTrust(
                TrustValidation(
                    outcome = checkTrust(
                        chain = signed?.firstHeader()?.certificateChain,
                        anchors = trust.accessCertificates?.invoke(),
                        at = at,
                        rule = TrustRule.CHAIN_TO_ANCHOR,
                    ),
                    source = ACCESS_CERTIFICATE_PROVIDERS,
                )
            )

            is ClientIdScheme.VerifierAttestation -> ClientTrust(verifierAttesterTrust(signed, at))
            // The wallet authenticates an unsigned DC API client through the platform-provided calling origin, and any
            // client_id it carries is ignored (OpenID4VP 1.0, A.3.1)
            is ClientIdScheme.PreRegistered if request is RequestParametersFrom.OpenId4VpDcApiUnsigned ->
                ClientTrust(TrustValidation(NotApplicable))

            is ClientIdScheme.PreRegistered -> preRegisteredTrust(request.parameters.clientIdWithoutPrefix)
            // There is no method to obtain a trusted key for this prefix (OpenID4VP 1.0, 5.9.3), and no request
            // without client_id, i.e. an unsigned DC API request, can be trusted beyond its calling origin
            is ClientIdScheme.RedirectUri, null -> ClientTrust(
                TrustValidation(
                    if (signed == null) NotApplicable
                    else Blocked(IllegalArgumentException("The client identifier prefix establishes no trusted key"))
                )
            )

            else -> customTrust(request, prefix)
        }
    }

    /**
     * The verifier attestation in the `jwt` header has to be issued by a party the wallet trusts: one of
     * [VerifierAttesters.certificates] issued its signing certificate, or one of [VerifierAttesters.keys] signed it
     * (OpenID4VP 1.0, 12). Its signature with its own key and its claims are validated by the caller.
     */
    private suspend fun verifierAttesterTrust(
        signed: RequestParametersFrom.RequestParametersSigned<AuthenticationRequestParameters>?,
        at: Instant,
    ): TrustValidation {
        val attestation = (signed?.jwsTyped?.jws as? JwsCompact)?.jwsHeader?.attestationJwt
            ?: return TrustValidation(Blocked(IllegalArgumentException("The request has no verifier attestation")))
        val attesters = trust.verifierAttesters
            ?: return TrustValidation(Blocked(IllegalStateException("No verifier attesters configured")))
        val chain = attestation.jwsHeader.certificateChain
        val outcome = if (chain != null) {
            checkTrust(chain, attesters.certificates?.invoke(), at, TrustRule.ISSUED_BY_ANCHOR_OR_LISTED)
        } else {
            val keys = attesters.keys?.invoke()
                ?: return TrustValidation(Blocked(IllegalStateException("No keys of verifier attesters configured")))
            if (keys.any { signatureCheck.verify(attestation, it).outcome == Passed }) Passed
            else Failed(IllegalArgumentException("The verifier attestation is not signed by a trusted attester"))
        }
        return TrustValidation(outcome, source = VERIFIER_ATTESTERS)
    }

    /** The client identifier has to be known in advance, with the keys requests of it are signed with. */
    private suspend fun preRegisteredTrust(clientId: String?): ClientTrust {
        val clients = trust.preRegisteredClients
            ?: return ClientTrust(
                TrustValidation(Blocked(IllegalStateException("No pre-registered clients configured")))
            )
        val keys = clientId?.let { clients.keys(it) }?.takeIf { it.isNotEmpty() }
            ?: return ClientTrust(
                TrustValidation(
                    Failed(IllegalArgumentException("client_id $clientId is not a pre-registered relying party")),
                    source = PRE_REGISTERED_CLIENTS,
                )
            )
        return ClientTrust(TrustValidation(Passed, source = PRE_REGISTERED_CLIENTS), keys)
    }

    private suspend fun customTrust(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        prefix: ClientIdScheme,
    ): ClientTrust {
        val custom = trust.clientIdentifierPrefixes
            ?: return ClientTrust(
                TrustValidation(
                    Blocked(IllegalStateException("No trust source for the client identifier prefix of $prefix"))
                )
            )
        return catching { custom.keys(request) }.fold(
            onSuccess = { ClientTrust(TrustValidation(Passed, source = CLIENT_IDENTIFIER_PREFIXES), it) },
            onFailure = { ClientTrust(TrustValidation(Failed(it), source = CLIENT_IDENTIFIER_PREFIXES)) },
        )
    }

    private fun RequestParametersFrom.RequestParametersSigned<AuthenticationRequestParameters>.firstHeader():
            JwsHeader? = when (val jws = jwsTyped.jws) {
        is JwsCompact -> jws.jwsHeader
        is JwsGeneral -> jws.jwsHeaders.firstOrNull()
        else -> null
    }

    private suspend fun validate(
        request: ExtractedRequest,
        policy: ValidationPolicy,
    ): RelyingPartyValidationResult {
        val timeScope = TimeScope(clock.now(), policy.timeLeeway)
        val access = evaluateAccessCertificate(
            chain = request.accessCertificateChain,
            signature = request.signature,
            clientId = request.clientId,
            anchors = trust.accessCertificates,
            source = ACCESS_CERTIFICATE_PROVIDERS,
            now = timeScope.now,
        )
        val registrations = request.registrationCertificates.map { (certificate, requests) ->
            val evaluation = evaluateRegistrationCertificate(
                certificate = certificate,
                accessIdentifier = access.identifier,
                purpose = RegistrationPurpose.Presentation(requests),
                anchors = trust.registrationCertificates,
                source = REGISTRATION_CERTIFICATE_PROVIDERS,
                signatureCheck = signatureCheck,
                maxValidity = maxRegistrationValidity,
                timeScope = timeScope,
            )
            val status = registrationStatus(
                evaluation = evaluation,
                policy = policy,
                now = timeScope.now,
                statusValidator = statusValidator,
                anchors = trust.registrationStatus,
            )
            val checks = evaluation.checks(status)
            certificate to ValidationReport.registrationCertificate(checks, policy, timeScope.now)
        }
        val report = ValidationReport.relyingParty(
            checks = RelyingPartyChecks(requestData = request.requestData),
            accessCertificate = ValidationReport.accessCertificate(access.checks, policy, timeScope.now),
            registrationCertificates = registrations.map { it.second },
            evaluatedAt = timeScope.now,
        )
        val untrustedRegistrations = registrations
            .filter { (it.second.checks as RegistrationCertificateChecks).parsing == Passed }
            .map { it.first.payload }
        val relyingParty = if (report.decision == ValidationDecision.ACCEPTED) {
            ValidatedRelyingParty(
                accessCertificateChain = requireNotNull(request.accessCertificateChain),
                identifier = requireNotNull(access.identifier),
                registrationCertificates = untrustedRegistrations,
            )
        } else null
        return RelyingPartyValidationResult(report, relyingParty, untrustedRegistrations)
    }

    /** A JAR, signed with the leaf of its `x5c`, with one WRPRC in `verifier_info` for its DCQL query. */
    private suspend fun extractSigned(
        jws: JwsCompact?,
        parameters: AuthenticationRequestParameters?,
    ): ExtractedRequest {
        if (jws == null)
            return unsigned("The request is no signed authorization request")
        if (parameters == null)
            return unsupported("The request is no authorization request")
        val chain = jws.jwsHeader.certificateChain?.takeIf { it.isNotEmpty() }
        val registrationCertificates = catching<Map<WrpRegistrationCertificate, List<WrpCredentialRequest>>> {
            requireNotNull(parameters.clientId) { "The request has no client_id" }
            val dcqlQuery = requireNotNull(parameters.dcqlQuery) { "The request has no DCQL query" }
            val verifierInfo = parameters.verifierInfo
                ?: throw MissingRegistrationCertificateException("The request has no verifier_info")
            val certificate = WrpRegistrationCertificate.WrpJwtRegistrationCertificate(
                verifierInfo.parseSingleRegistrationCertificate()
            )
            mapOf(certificate to dcqlQuery.credentials.map { WrpCredentialRequest.WrpDcqlCredentialQuery(it) })
        }
        return ExtractedRequest(
            accessCertificateChain = chain,
            signature = chain?.let { signatureCheck.verify(jws).outcome }
                ?: Blocked(IllegalArgumentException("The request transports no certificate chain")),
            clientId = parameters.clientId.orEmpty(),
            requestData = registrationCertificates.toOutcome(),
            registrationCertificates = registrationCertificates.getOrElse { emptyMap() },
        )
    }

    /**
     * An ISO mdoc request, every document request authenticated by one WRPAC over [sessionTranscript], each with
     * the WRPRC for it in `euWrprc`.
     */
    private suspend fun extractMdoc(
        deviceRequest: DeviceRequest,
        sessionTranscript: SessionTranscript,
    ): ExtractedRequest {
        if (deviceRequest.readerAuthAll.isNullOrEmpty() && deviceRequest.docRequests.all { it.readerAuth == null })
            return unsigned("The request has no reader authentication")
        val chain = ReaderAuthenticationVerifier()(deviceRequest, sessionTranscript)
        val registrationCertificates = catching<Map<WrpRegistrationCertificate, List<WrpCredentialRequest>>> {
            if (deviceRequest.docRequests.all { it.itemsRequest.value.requestInfo?.euWrprc == null }) {
                throw MissingRegistrationCertificateException("No DocRequest contains a registration certificate")
            }
            deviceRequest.docRequests.map { docRequest ->
                val encoded = docRequest.itemsRequest.value.requestInfo?.euWrprc
                    ?: throw InvalidRegistrationCertificateException(
                        "A DocRequest has no registration certificate, while others have one"
                    )
                val certificate = catchingUnwrapped {
                    val cose = coseCompliantSerializer.decodeFromByteArray<CoseSigned<ByteArray>>(encoded)
                    WrpRegistrationCertificate.WrpCwtRegistrationCertificate(
                        cose = cose,
                        payload = parseWrprcCose(cose),
                    )
                }.getOrElse { throw InvalidRegistrationCertificateException("A WRPRC can not be parsed", it) }
                certificate to WrpCredentialRequest.WrpDocRequest(docRequest)
            }.groupBy({ it.first }, { it.second })
        }
        return ExtractedRequest(
            accessCertificateChain = chain.getOrNull(),
            signature = chain.toOutcome(),
            clientId = null,
            requestData = registrationCertificates.toOutcome(),
            registrationCertificates = registrationCertificates.getOrElse { emptyMap() },
        )
    }

    /**
     * A request that is not signed, so there is no WRPAC whose signature could be verified, and no WRPRC is bound to
     * the request: its WRPRCs are not extracted, as anyone can copy them into a request.
     */
    private fun unsigned(message: String) = ExtractedRequest(
        accessCertificateChain = null,
        signature = NotApplicable,
        clientId = null,
        requestData = Failed(UnsupportedWrpRequestException(message)),
        registrationCertificates = emptyMap(),
    )

    private fun unsupported(message: String) = ExtractedRequest(
        accessCertificateChain = null,
        signature = Blocked(),
        clientId = null,
        requestData = Failed(UnsupportedWrpRequestException(message)),
        registrationCertificates = emptyMap(),
    )

    /** What a request transports of its relying party. */
    private class ExtractedRequest(
        val accessCertificateChain: CertificateChain?,
        /** Whether the request is signed by the leaf of [accessCertificateChain]. */
        val signature: CheckOutcome,
        /** The client identifier of a JAR, `null` for mdoc reader authentication. */
        val clientId: String?,
        /** Whether the WRPRCs and the credential requests could be extracted. */
        val requestData: CheckOutcome,
        val registrationCertificates: Map<WrpRegistrationCertificate, List<WrpCredentialRequest>>,
    )

    private companion object {
        const val ACCESS_CERTIFICATE_PROVIDERS = "WRPAC providers"
        const val REGISTRATION_CERTIFICATE_PROVIDERS = "WRPRC providers"
        const val VERIFIER_ATTESTERS = "verifier attesters"
        const val PRE_REGISTERED_CLIENTS = "pre-registered clients"
        const val CLIENT_IDENTIFIER_PREFIXES = "client identifier prefixes"
    }
}

/**
 * The [report] of validating the relying party of a request, see [RelyingPartyChecks], and the [relyingParty] if it
 * has been accepted. A failed `requestAuthorization` of a WRPRC carries an [UnregisteredRequestException], which
 * tells which credentials or claims are not registered.
 */
data class RelyingPartyValidationResult(
    val report: ValidationReport,
    val relyingParty: ValidatedRelyingParty?,
    /**
     * What the WRPRCs of the request say whose `parsing` passed, whatever the decision of [report], e.g. to show the
     * name and the purposes of a relying party next to the warning that its WRPRC is revoked. They are not verified
     * unless [relyingParty] is present: their signer may not be trusted, nor their status valid, nor they be issued
     * to the relying party that signed the request, so use them only to show them to the user, marked as such.
     */
    val untrustedRegistrations: List<WrpPayload> = emptyList(),
) {
    init {
        require(report.checks is RelyingPartyChecks) { "Report has to be a relying party report" }
        require((relyingParty != null) == (report.decision == ValidationDecision.ACCEPTED)) {
            "A relying party is present if and only if the report is accepted"
        }
        require(relyingParty == null || relyingParty.registrationCertificates == untrustedRegistrations) {
            "The registrations of an accepted relying party are the untrusted registrations too"
        }
    }
}

/** A wallet-relying party that passed every required check. */
data class ValidatedRelyingParty(
    val accessCertificateChain: CertificateChain,
    /** The identifier of the relying party in its WRPAC, which every WRPRC is issued to. */
    val identifier: WrpacIdentifier,
    /** What the relying party is registered for, e.g. to show its name and its purposes to the user. */
    val registrationCertificates: List<WrpPayload>,
)

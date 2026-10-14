package at.asitplus.wallet.lib.agent.relyingParty

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.NFCHandover
import at.asitplus.dcapi.request.IsoMdocRequest
import at.asitplus.etsi.relyingParty.WrpClaim
import at.asitplus.etsi.relyingParty.WrpClaimPathSegment
import at.asitplus.etsi.relyingParty.WrpCredential
import at.asitplus.etsi.relyingParty.WrpCredentialMeta
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DocRequest
import at.asitplus.iso.DocRequestInfo
import at.asitplus.iso.EncryptionInfo
import at.asitplus.iso.EncryptionParameters
import at.asitplus.iso.ReaderAuthenticationAll
import at.asitplus.iso.SessionTranscript
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants.VerifierInfo.REGISTRATION_CERT_FORMAT
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.VerifierInfo
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.IndexSegment
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NameSegment
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.agent.validation.relyingParty.InvalidRegistrationCertificateException
import at.asitplus.wallet.lib.agent.validation.relyingParty.MissingRegistrationCertificateException
import at.asitplus.wallet.lib.agent.validation.relyingParty.UnsupportedWrpRequestException
import at.asitplus.wallet.lib.cbor.SignCoseDetached
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.validation.AccessCertificateChecks
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.NamedCheck
import at.asitplus.wallet.lib.validation.RegistrationCertificateChecks
import at.asitplus.wallet.lib.validation.RelyingPartyChecks
import at.asitplus.wallet.lib.validation.RelyingPartyTrustAnchors
import at.asitplus.wallet.lib.validation.RelyingPartyValidationResult
import at.asitplus.wallet.lib.validation.RelyingPartyValidator
import at.asitplus.wallet.lib.validation.StatusPolicy
import at.asitplus.wallet.lib.validation.StatusValidator
import at.asitplus.wallet.lib.validation.TimelinessException
import at.asitplus.wallet.lib.validation.TokenStatusException
import at.asitplus.wallet.lib.validation.TrustPolicy
import at.asitplus.wallet.lib.validation.UnregisteredRequestException
import at.asitplus.wallet.lib.validation.ValidationDecision.ACCEPTED
import at.asitplus.wallet.lib.validation.ValidationDecision.REJECTED
import at.asitplus.wallet.lib.validation.ValidationPolicy
import at.asitplus.wallet.lib.validation.ValidationReport
import io.github.z4kn4fein.semver.Version
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.encodeToByteArray

val RelyingPartyValidatorTest by matrixSuite {

    "a request of a registered relying party is accepted" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(fixture.wrpIdentifier)

        val result = fixture.validate(fixture.request(payload))

        result.report.decision shouldBe ACCEPTED
        result.relyingParty.shouldNotBeNull().apply {
            identifier.identifier shouldBe fixture.wrpIdentifier
            registrationCertificates.shouldBeSingleton().first() shouldBe payload
        }
        result.untrustedRegistrations shouldBe listOf(payload)
    }

    "a WRPRC registering all elements of an array authorizes requests for each of them, not for the array" {
        val fixture = buildWrpFixture()
        val nationalities = WrpCredential(
            format = "dc+sd-jwt",
            meta = WrpCredentialMeta(vctValues = listOf(PID_VCT)),
            claim = listOf(
                WrpClaim(listOf(WrpClaimPathSegment.Name("nationalities"), WrpClaimPathSegment.AllElements))
            ),
        )
        val payload = buildWrpPayload(fixture.wrpIdentifier, credentials = listOf(nationalities))
        val elements = sdJwtRequest(
            DCQLClaimsPathPointer(nonEmptyListOf(NameSegment("nationalities"), IndexSegment(0U))),
            DCQLClaimsPathPointer(nonEmptyListOf(NameSegment("nationalities"), IndexSegment(1U))),
        )
        val array = sdJwtRequest(DCQLClaimsPathPointer("nationalities"))

        fixture.validate(fixture.request(payload, elements)).apply {
            report.decision shouldBe ACCEPTED
            relyingParty.shouldNotBeNull().registrationCertificates.single() shouldBe payload
        }
        fixture.validate(fixture.request(payload, array)).apply {
            report.decision shouldBe REJECTED
            registrationChecks().requestAuthorization.shouldBeInstanceOf<CheckOutcome.Failed>()
                .throwable.shouldBeInstanceOf<UnregisteredRequestException>()
        }
    }

    "a revoked WRPRC is rejected, with its status" {
        val fixture = buildWrpFixture()

        val payload = buildWrpPayload(fixture.wrpIdentifier, statusListIdx = 1)
        val result = fixture.validate(fixture.request(payload))

        result.report.decision shouldBe REJECTED
        result.relyingParty.shouldBeNull()
        // what the WRPRC says, to show it next to the warning
        result.untrustedRegistrations shouldBe listOf(payload)
        result.registrationChecks().status.mechanisms.shouldBeSingleton().first().outcome
            .shouldBeInstanceOf<CheckOutcome.Failed>().throwable.shouldBeInstanceOf<TokenStatusException>()
    }

    "unregistered claims are rejected, naming the request" {
        val fixture = buildWrpFixture()
        val request = mdocDcqlRequest(claimNames = listOf("given_name", "portrait"))

        val result = fixture.validate(fixture.request(buildWrpPayload(fixture.wrpIdentifier), request))

        result.report.decision shouldBe REJECTED
        result.registrationChecks().requestAuthorization.shouldBeInstanceOf<CheckOutcome.Failed>()
            .throwable.shouldBeInstanceOf<UnregisteredRequestException>().requests.shouldBeSingleton()
    }

    "a WRPRC issued to another relying party is rejected" {
        val fixture = buildWrpFixture()

        val result = fixture.validate(fixture.request(buildWrpPayload("another relying party")))

        result.registrationChecks().linkage.shouldBeInstanceOf<CheckOutcome.Failed>()
        result.report.decision shouldBe REJECTED
    }

    "a client identifier other than the hash of the WRPAC is rejected" {
        val fixture = buildWrpFixture()
        val parameters = fixture.parameters(buildWrpPayload(fixture.wrpIdentifier)).copy(clientId = "x509_hash:AAAA")

        val result = fixture.validate(fixture.signedByWrp(parameters))

        result.accessChecks().clientId.shouldBeInstanceOf<CheckOutcome.Failed>()
        result.report.decision shouldBe REJECTED
    }

    "without anchors, trust is blocked and the request is rejected" {
        val fixture = buildWrpFixture()

        val result = RelyingPartyValidator(statusValidator = fixture.statusValidator())
            .validate(fixture.request(buildWrpPayload(fixture.wrpIdentifier)), policy)

        result.accessChecks().trust.outcome.shouldBeInstanceOf<CheckOutcome.Blocked>()
        result.registrationChecks().trust.outcome.shouldBeInstanceOf<CheckOutcome.Blocked>()
        result.report.decision shouldBe REJECTED
    }

    "the clock of the validator is honored: an expired WRPRC is rejected, and its status is not resolved" {
        val fixture = buildWrpFixture(validity = 30.days)
        val payload = buildWrpPayload(fixture.wrpIdentifier, exp = Clock.System.now() + 1.days)
        val tomorrow = object : Clock {
            override fun now(): Instant = Clock.System.now() + 2.days
        }

        val result = fixture.validator(tomorrow).validate(fixture.request(payload), policy)

        result.registrationChecks().apply {
            timeliness.shouldBeInstanceOf<CheckOutcome.Failed>().throwable.shouldBeInstanceOf<TimelinessException>()
            status.claim.shouldBeInstanceOf<CheckOutcome.Blocked>()
        }
        result.report.decision shouldBe REJECTED
    }

    "an mdoc request of a registered relying party is accepted, authenticated over the session transcript" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(fixture.wrpIdentifier)
        val wrprc = coseCompliantSerializer.encodeToByteArray(signWrprcCose(fixture.wrprcSigningKeyMaterial, payload))
        val docRequest = mdocDocRequest().let {
            val itemsRequest = it.itemsRequest.value.copy(requestInfo = DocRequestInfo(euWrprc = wrprc))
            it.copy(itemsRequest = ByteStringWrapper(itemsRequest))
        }
        val transcript = SessionTranscript.forDcApi(DCAPIHandover(DCAPIHandover.TYPE_DCAPI, ByteArray(32)))
        val otherTranscript = SessionTranscript.forDcApi(DCAPIHandover(DCAPIHandover.TYPE_DCAPI, ByteArray(32) { 1 }))
        val request = fixture.isoRequest(docRequest, transcript)

        fixture.validator().validate(request, transcript, policy).apply {
            report.decision shouldBe ACCEPTED
            relyingParty.shouldNotBeNull().registrationCertificates.shouldBeSingleton().first()
                .subjectIdentifier shouldBe fixture.wrpIdentifier
        }
        fixture.validator().validate(request, otherTranscript, policy).apply {
            report.decision shouldBe REJECTED
            accessChecks().signature.shouldBeInstanceOf<CheckOutcome.Failed>()
        }
    }

    "a device request of a proximity presentation with a WRPRC is accepted, authenticated over its transcript" {
        val fixture = buildWrpFixture()
        val transcript = nfcTranscript()

        fixture.validator().validate(fixture.proximityRequest(transcript), transcript, policy).apply {
            report.decision shouldBe ACCEPTED
            accessChecks().signature shouldBe CheckOutcome.Passed
            report.children.map { it.decision } shouldBe listOf(ACCEPTED, ACCEPTED)
            relyingParty.shouldNotBeNull().apply {
                identifier.identifier shouldBe fixture.wrpIdentifier
                registrationCertificates.shouldBeSingleton().first().subjectIdentifier shouldBe fixture.wrpIdentifier
            }
        }
    }

    "a device request authenticated over another session transcript fails the signature of the WRPAC" {
        val fixture = buildWrpFixture()
        val deviceRequest = fixture.proximityRequest(nfcTranscript())

        fixture.validator().validate(deviceRequest, nfcTranscript(handoverSelect = byteArrayOf(2)), policy).apply {
            report.decision shouldBe REJECTED
            accessChecks().signature.shouldBeInstanceOf<CheckOutcome.Failed>()
            relyingParty.shouldBeNull()
        }
    }

    "a device request altered after its reader authentication fails the signature of the WRPAC" {
        val fixture = buildWrpFixture()
        val transcript = nfcTranscript()
        val deviceRequest = fixture.proximityRequest(transcript)
        val altered = deviceRequest.copy(
            docRequests = arrayOf(fixture.docRequestWithWrprc(claimNames = listOf("given_name")))
        )

        fixture.validator().validate(altered, transcript, policy).apply {
            report.decision shouldBe REJECTED
            accessChecks().signature.shouldBeInstanceOf<CheckOutcome.Failed>()
            // the altered request is registered, but the WRPRC can't be linked to a WRPAC whose signature failed
            report.checks.shouldBeInstanceOf<RelyingPartyChecks>().requestData shouldBe CheckOutcome.Passed
            registrationChecks().linkage.shouldBeInstanceOf<CheckOutcome.Blocked>()
        }
    }

    "a device request without reader authentication is reported as unsigned, not as forged" {
        val fixture = buildWrpFixture()
        val transcript = nfcTranscript()
        val unauthenticated = fixture.proximityRequest(transcript).copy(readerAuthAll = null)

        fixture.validator().validate(unauthenticated, transcript, policy).apply {
            report.decision shouldBe REJECTED
            relyingParty.shouldBeNull()
            report.checks.shouldBeInstanceOf<RelyingPartyChecks>().requestData
                .shouldBeInstanceOf<CheckOutcome.Failed>().throwable.shouldBeInstanceOf<UnsupportedWrpRequestException>()
            accessChecks().apply {
                parsing shouldBe CheckOutcome.NotApplicable
                signature shouldBe CheckOutcome.NotApplicable
            }
            // its WRPRCs are not bound to the request, as anyone can copy them into one
            report.children.drop(1).shouldBeEmpty()
            untrustedRegistrations.shouldBeEmpty()
            // a wallet may continue past these after warning the user, but past no integrity check
            report.allNamedChecks().filterNot { it.satisfied }.map { it.name }.toSet() shouldBe
                    setOf("requestData", "registration", "trust", "timeliness")
        }
    }

    "a device request with a reader authentication that does not verify is reported as forged" {
        val fixture = buildWrpFixture()
        val transcript = nfcTranscript()
        // signed by another key than the one of the WRPAC in its x5chain
        val forged = fixture.isoRequest(fixture.docRequestWithWrprc(), transcript, signingKey = EphemeralKeyWithoutCert())
            .parameters.isoMdocRequest.deviceRequest

        fixture.validator().validate(forged, transcript, policy).apply {
            report.decision shouldBe REJECTED
            accessChecks().signature.shouldBeInstanceOf<CheckOutcome.Failed>()
        }
    }

    "a request without a WRPRC is rejected as missing one" {
        val fixture = buildWrpFixture()
        val parameters = fixture.parameters(buildWrpPayload(fixture.wrpIdentifier)).copy(verifierInfo = null)

        val result = fixture.validate(fixture.signedByWrp(parameters))

        result.report.checks.shouldBeInstanceOf<RelyingPartyChecks>().apply {
            requestData shouldBe CheckOutcome.Passed
            registration.shouldBeInstanceOf<CheckOutcome.Failed>().throwable
                .shouldBeInstanceOf<MissingRegistrationCertificateException>()
        }
        result.report.children.drop(1).shouldBeEmpty()
        result.accessChecks().signature shouldBe CheckOutcome.Passed
    }

    "a WRPRC that can not be parsed fails the registration of a relying party, not its request" {
        val fixture = buildWrpFixture()
        val parameters = fixture.parameters(buildWrpPayload(fixture.wrpIdentifier))
            .copy(verifierInfo = nonEmptyListOf(VerifierInfo(REGISTRATION_CERT_FORMAT, "not-a-jws")))

        fixture.validate(fixture.signedByWrp(parameters)).apply {
            report.decision shouldBe REJECTED
            report.checks.shouldBeInstanceOf<RelyingPartyChecks>().apply {
                requestData shouldBe CheckOutcome.Passed
                registration.shouldBeInstanceOf<CheckOutcome.Failed>().throwable
                    .shouldBeInstanceOf<InvalidRegistrationCertificateException>()
            }
            // the request is authenticated by a trusted WRPAC, so a wallet may continue after warning the user
            report.allNamedChecks().filterNot { it.satisfied }.map { it.name } shouldBe listOf("registration")
            untrustedRegistrations.shouldBeEmpty()
        }
    }

    "a device request without WRPRCs fails the registration of a proximity reader, not its request" {
        val fixture = buildWrpFixture()
        val transcript = nfcTranscript()
        val deviceRequest = fixture.isoRequest(mdocDocRequest(), transcript).parameters.isoMdocRequest.deviceRequest

        fixture.validator().validate(deviceRequest, transcript, policy).apply {
            report.decision shouldBe REJECTED
            accessChecks().signature shouldBe CheckOutcome.Passed
            report.checks.shouldBeInstanceOf<RelyingPartyChecks>().apply {
                requestData shouldBe CheckOutcome.Passed
                registration.shouldBeInstanceOf<CheckOutcome.Failed>().throwable
                    .shouldBeInstanceOf<MissingRegistrationCertificateException>()
            }
        }
    }

    "an unsigned request is not supported" {
        val fixture = buildWrpFixture()
        val unsigned = RequestParametersFrom.Json(
            jsonString = "",
            parameters = fixture.parameters(buildWrpPayload(fixture.wrpIdentifier)),
        )

        fixture.validate(unsigned).apply {
            report.checks.shouldBeInstanceOf<RelyingPartyChecks>().requestData
                .shouldBeInstanceOf<CheckOutcome.Failed>().throwable.shouldBeInstanceOf<UnsupportedWrpRequestException>()
            accessChecks().signature shouldBe CheckOutcome.NotApplicable
            report.checks.shouldBeInstanceOf<RelyingPartyChecks>().registration
                .shouldBeInstanceOf<CheckOutcome.Blocked>()
        }
    }
}

/** The status list tokens are signed by a key without certificate, so their signers are not authorized. */
private val policy = ValidationPolicy(
    trust = TrustPolicy.RequireAuthorizedSigner,
    status = StatusPolicy.RequireClaim(signerTrust = TrustPolicy.IntegrityOnly),
    timeLeeway = 5.minutes,
    requireTimeliness = true,
)

private fun WrpFixture.statusValidator() =
    StatusValidator(StatusListTokenResolver { buildStatusListToken(it, revokedIndex = 1) })

private fun WrpFixture.validator(clock: Clock = Clock.System) = RelyingPartyValidator(
    trust = RelyingPartyTrustAnchors(accessCertificates = trustAnchors, registrationCertificates = trustAnchors),
    statusValidator = statusValidator(),
    clock = clock,
)

private suspend fun WrpFixture.validate(request: RequestParametersFrom<*>) = validator().validate(request, policy)

private suspend fun WrpFixture.parameters(
    payload: WrpPayload,
    request: CredentialPresentationRequest = mdocDcqlRequest(),
) = AuthenticationRequestParameters(
    clientId = clientId,
    verifierInfo = nonEmptyListOf(
        VerifierInfo(REGISTRATION_CERT_FORMAT, signWrprc(wrprcSigningKeyMaterial, payload))
    ),
    dcqlQuery = (request as CredentialPresentationRequest.DCQLRequest).dcqlQuery,
)

private suspend fun WrpFixture.request(
    payload: WrpPayload,
    request: CredentialPresentationRequest = mdocDcqlRequest(),
) = signedByWrp(parameters(payload, request))

private const val PID_VCT = "urn:eudi:pid:1"

/** A DCQL request for an SD-JWT VC of [PID_VCT] with the claims at [paths]. */
private fun sdJwtRequest(vararg paths: DCQLClaimsPathPointer) = CredentialPresentationRequest.DCQLRequest(
    DCQLQuery(
        credentials = DCQLCredentialQueryList(
            nonEmptyListOf(
                DCQLSdJwtCredentialQuery(
                    id = DCQLCredentialQueryIdentifier("pid"),
                    meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(vctValues = listOf(PID_VCT)),
                    claims = DCQLClaimsQueryList(paths.map { DCQLJsonClaimsQuery(path = it) }.toNonEmptyList()),
                )
            )
        )
    )
)

/** The named checks of this report and of its children. */
private fun ValidationReport.allNamedChecks(): List<NamedCheck> = namedChecks + children.flatMap { it.allNamedChecks() }

private fun RelyingPartyValidationResult.accessChecks() =
    report.children.first().checks.shouldBeInstanceOf<AccessCertificateChecks>()

private fun RelyingPartyValidationResult.registrationChecks() =
    report.children.drop(1).shouldBeSingleton().first().checks.shouldBeInstanceOf<RegistrationCertificateChecks>()

/** The session transcript of a proximity presentation with NFC engagement (ISO/IEC 18013-5:2021, 9.1.5.1). */
private fun nfcTranscript(handoverSelect: ByteArray = byteArrayOf(1)) = SessionTranscript.forNfc(
    deviceEngagementBytes = byteArrayOf(0x0a),
    eReaderKeyBytes = byteArrayOf(0x0b),
    nfcHandover = NFCHandover(handoverSelect = handoverSelect, handoverRequest = null),
)

/** A document request carrying the WRPRC of the relying party in `euWrprc`. */
private suspend fun WrpFixture.docRequestWithWrprc(
    claimNames: List<String> = listOf("given_name", "family_name", "birth_date"),
): DocRequest {
    val payload = buildWrpPayload(wrpIdentifier)
    val wrprc = coseCompliantSerializer.encodeToByteArray(signWrprcCose(wrprcSigningKeyMaterial, payload))
    return mdocDocRequest(claimNames = claimNames).let {
        val itemsRequest = it.itemsRequest.value.copy(requestInfo = DocRequestInfo(euWrprc = wrprc))
        it.copy(itemsRequest = ByteStringWrapper(itemsRequest))
    }
}

/** A device request of a proximity presentation, authenticated by the WRPAC over [transcript]. */
private suspend fun WrpFixture.proximityRequest(transcript: SessionTranscript): DeviceRequest =
    isoRequest(docRequestWithWrprc(), transcript).parameters.isoMdocRequest.deviceRequest

/**
 * An ISO mdoc request over the DC API, authenticated with `readerAuthAll` over [transcript] by [signingKey], with the
 * chain of the WRPAC in its `x5chain`.
 */
private suspend fun WrpFixture.isoRequest(
    docRequest: DocRequest,
    transcript: SessionTranscript,
    signingKey: KeyMaterial = wrpKey,
): RequestParametersFrom.IsoMdocDcApi {
    val unsigned = DeviceRequest(Version(1, 1), docRequests = arrayOf(docRequest))
    val readerAuth = SignCoseDetached<ByteArray>(
        signingKey,
        unprotectedHeaderModifier = { header, _ ->
            header?.copy(certificateChain = wrpacChain.map { it.encodeToDer() })
        },
    )(
        protectedHeader = null,
        unprotectedHeader = CoseHeader(),
        payload = ReaderAuthenticationAll.detachedPayload(unsigned, transcript),
        serializer = ByteArraySerializer(),
    ).getOrThrow()
    return RequestParametersFrom.IsoMdocDcApi(
        parameters = RequestParametersFrom.IsoMdocDcApi.IsoMdocRequestWrapper(
            IsoMdocRequest(
                unsigned.copy(readerAuthAll = arrayOf(readerAuth)),
                EncryptionInfo(
                    "dcapi",
                    EncryptionParameters(recipientPublicKey = wrpKey.publicKey.toCoseKey().getOrThrow()),
                ),
            )
        ),
        jsonString = "",
        callingOrigin = "https://example.com",
    )
}

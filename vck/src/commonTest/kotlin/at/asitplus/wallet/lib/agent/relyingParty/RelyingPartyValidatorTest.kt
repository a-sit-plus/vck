package at.asitplus.wallet.lib.agent.relyingParty

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.NFCHandover
import at.asitplus.dcapi.request.IsoMdocRequest
import at.asitplus.etsi.relyingParty.WrpClaim
import at.asitplus.etsi.relyingParty.WrpClaimPathSegment
import at.asitplus.etsi.relyingParty.WrpClaimValue
import at.asitplus.etsi.relyingParty.WrpCredential
import at.asitplus.etsi.relyingParty.WrpCredentialMeta
import at.asitplus.etsi.relyingParty.WrpIntermediary
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DocRequest
import at.asitplus.iso.DocRequestInfo
import at.asitplus.iso.EncryptionInfo
import at.asitplus.iso.EncryptionParameters
import at.asitplus.iso.ReaderAuthentication
import at.asitplus.iso.ReaderAuthenticationAll
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.sha256
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants.VerifierInfo.REGISTRATION_CERT_FORMAT
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.VerifierInfo
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.IndexSegment
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NameSegment
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NullSegment
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.KeyWithFixedCert
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.agent.validation.relyingParty.InvalidRegistrationCertificateException
import at.asitplus.wallet.lib.agent.validation.relyingParty.MissingRegistrationCertificateException
import at.asitplus.wallet.lib.agent.validation.relyingParty.UnsupportedWrpRequestException
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrpCredentialRequest
import at.asitplus.wallet.lib.cbor.SignCoseDetached
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.validation.AccessCertificateChecks
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.NamedCheck
import at.asitplus.wallet.lib.validation.RegistrationCertificateChecks
import at.asitplus.wallet.lib.validation.RegistrationPolicy
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
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

val RelyingPartyValidatorTest by matrixSuite {

    "a request of a registered relying party is accepted" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(fixture.wrpIdentifier)

        val result = fixture.validate(fixture.request(payload))

        result.report.decision shouldBe ACCEPTED
        result.relyingParty.shouldNotBeNull().apply {
            identifier.shouldNotBeNull().identifier shouldBe fixture.wrpIdentifier
            registrationCertificates.shouldBeSingleton().first() shouldBe payload
            intermediated shouldBe false
        }
        result.untrustedRegistrations shouldBe listOf(payload)
    }

    "a request with its WRPRC base64url-encoded in verifier_info (ETSI TS 119 472-2, RO_REQ-09) is accepted" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(fixture.wrpIdentifier)
        val encoded = signWrprc(fixture.wrprcSigningKeyMaterial, payload).encodeToByteArray()
            .encodeToString(Base64UrlStrict)
        val parameters = fixture.parameters(payload)
            .copy(verifierInfo = nonEmptyListOf(VerifierInfo(REGISTRATION_CERT_FORMAT, encoded)))

        val result = fixture.validate(fixture.signedByWrp(parameters))

        result.report.decision shouldBe ACCEPTED
        result.relyingParty.shouldNotBeNull().registrationCertificates.shouldBeSingleton().first() shouldBe payload
    }

    "a request of an intermediary, with the WRPRC of the relying party naming it, is accepted" {
        val fixture = buildWrpFixture(wrpIdentifier = INTERMEDIARY)
        val payload = intermediatedPayload()

        val result = fixture.validate(fixture.request(payload))

        result.report.decision shouldBe ACCEPTED
        result.relyingParty.shouldNotBeNull().apply {
            identifier.shouldNotBeNull().identifier shouldBe INTERMEDIARY
            registrationCertificates.shouldBeSingleton().first().subjectIdentifier shouldBe RELYING_PARTY
            intermediated shouldBe true
        }
    }

    "a WRPRC naming another intermediary fails the linkage" {
        val fixture = buildWrpFixture(wrpIdentifier = INTERMEDIARY)
        val payload = intermediatedPayload(intermediary = "LEIXG-ANOTHER-INTERMEDIARY")

        val result = fixture.validate(fixture.request(payload))

        result.report.decision shouldBe REJECTED
        result.registrationChecks().linkage.shouldBeInstanceOf<CheckOutcome.Failed>()
    }

    "a WRPRC naming an intermediary also links to the WRPAC of its own subject" {
        val fixture = buildWrpFixture(wrpIdentifier = RELYING_PARTY)

        fixture.validate(fixture.request(intermediatedPayload())).apply {
            report.decision shouldBe ACCEPTED
            relyingParty.shouldNotBeNull().intermediated shouldBe false
        }
    }

    "an mdoc request of an intermediary, with the WRPRC of the relying party naming it, is accepted" {
        val fixture = buildWrpFixture(wrpIdentifier = INTERMEDIARY)
        val transcript = SessionTranscript.DcApi(DCAPIHandover(DCAPIHandover.TYPE_DCAPI, ByteArray(32)))
        val request = fixture.isoRequest(fixture.docRequestWithWrprc(payload = intermediatedPayload()), transcript)

        fixture.validator().validate(request, transcript, policy).apply {
            report.decision shouldBe ACCEPTED
            relyingParty.shouldNotBeNull().apply {
                identifier.shouldNotBeNull().identifier shouldBe INTERMEDIARY
                intermediated shouldBe true
            }
        }
    }

    "an mdoc request with WRPRCs of different relying parties fails the registration" {
        val fixture = buildWrpFixture(wrpIdentifier = INTERMEDIARY)
        val transcript = SessionTranscript.DcApi(DCAPIHandover(DCAPIHandover.TYPE_DCAPI, ByteArray(32)))
        val other = buildWrpPayload("LEIXG-ANOTHER-RELYING-PARTY").copy(intermediary = WrpIntermediary(INTERMEDIARY))
        val request = fixture.isoRequest(
            fixture.docRequestWithWrprc(payload = intermediatedPayload()),
            transcript,
            fixture.docRequestWithWrprc(payload = other),
        )

        fixture.validator().validate(request, transcript, policy).apply {
            report.decision shouldBe REJECTED
            report.checks.shouldBeInstanceOf<RelyingPartyChecks>().registration
                .shouldBeInstanceOf<CheckOutcome.Failed>().throwable
                .shouldBeInstanceOf<InvalidRegistrationCertificateException>()
        }
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

    "only the root vct is exempt from claim registration" - {
        listOf(
            DCQLClaimsPathPointer("vct") to ACCEPTED,
            DCQLClaimsPathPointer("address", "vct") to REJECTED,
        ).asData() test { (path, decision) ->
            val fixture = buildWrpFixture()
            val credential = WrpCredential(
                format = "dc+sd-jwt",
                meta = WrpCredentialMeta(vctValues = listOf(PID_VCT)),
                claim = listOf(WrpClaim.named("given_name")),
            )
            val payload = buildWrpPayload(fixture.wrpIdentifier, credentials = listOf(credential))

            fixture.validate(fixture.request(payload, sdJwtRequest(path))).report.decision shouldBe decision
        }
    }

    "registered JSON paths cover only their selected claims and descendants" - {
        listOf(
            Triple("[\"address\"]", "[\"address\"]", ACCEPTED),
            Triple("[\"address\"]", "[\"address\",\"locality\"]", ACCEPTED),
            Triple("[\"address\",\"locality\"]", "[\"address\"]", REJECTED),
            Triple("[\"degrees\",null,\"type\"]", "[\"degrees\",1,\"type\"]", ACCEPTED),
            Triple("[\"degrees\",null,\"type\"]", "[\"degrees\",null,\"type\"]", ACCEPTED),
            Triple("[\"degrees\",null,\"type\"]", "[\"degrees\",\"1\",\"type\"]", REJECTED),
            Triple("[\"degrees\",1,\"type\"]", "[\"degrees\",null,\"type\"]", REJECTED),
            Triple("[\"degrees\",1,\"type\"]", "[\"degrees\",0,\"type\"]", REJECTED),
            Triple("[\"degrees\",1,\"type\"]", "[\"degrees\",1,\"type\"]", ACCEPTED),
            Triple("[\"degrees\"]", "[\"degrees\",null,\"university\"]", ACCEPTED),
            Triple("[\"nationalities\",null]", "[\"nationalities\",null]", ACCEPTED),
            Triple("[\"nationalities\",null]", "[\"nationalities\",0]", ACCEPTED),
            Triple("[\"nationalities\",null]", "[\"nationalities\"]", REJECTED),
            Triple("[\"nationalities\",0]", "[\"nationalities\",null]", REJECTED),
            Triple("[\"age_equal_or_over\",\"18\"]", "[\"age_equal_or_over\",\"18\"]", ACCEPTED),
        ).asData(nameFn = { (grant, request, _) -> "$grant covers $request" }) test { (grant, request, decision) ->
            val fixture = buildWrpFixture()
            val credential = WrpCredential(
                format = "dc+sd-jwt",
                meta = WrpCredentialMeta(vctValues = listOf(PID_VCT)),
                claim = listOf(joseCompliantSerializer.decodeFromString(WrpClaim.serializer(), """{"path":$grant}""")),
            )
            val payload = buildWrpPayload(fixture.wrpIdentifier, credentials = listOf(credential))
            val path = joseCompliantSerializer.decodeFromString(DCQLClaimsPathPointer.serializer(), request)
            val result = fixture.validate(fixture.request(payload, sdJwtRequest(path)))

            result.report.decision shouldBe decision
            if (decision == ACCEPTED) {
                result.registrationChecks().requestAuthorization shouldBe CheckOutcome.Passed
            } else {
                result.registrationChecks().requestAuthorization.shouldBeInstanceOf<CheckOutcome.Failed>()
                    .throwable.shouldBeInstanceOf<UnregisteredRequestException>()
            }
        }
    }

    "mdoc registration matches exactly namespace and element" - {
        listOf(
            "[\"$DEFAULT_DOCTYPE\",\"given_name\"]" to ACCEPTED,
            "[\"$DEFAULT_DOCTYPE\"]" to REJECTED,
            "[\"$DEFAULT_DOCTYPE\",null]" to REJECTED,
            "[\"$DEFAULT_DOCTYPE\",0]" to REJECTED,
            "[\"$DEFAULT_DOCTYPE\",\"given_name\",\"child\"]" to REJECTED,
        ).asData() test { (grant, decision) ->
            val fixture = buildWrpFixture()
            val credential = defaultMdocCredential().copy(
                claim = listOf(joseCompliantSerializer.decodeFromString(WrpClaim.serializer(), """{"path":$grant}""")),
            )
            val payload = buildWrpPayload(fixture.wrpIdentifier, credentials = listOf(credential))
            fixture.validate(fixture.request(payload, mdocDcqlRequest(claimNames = listOf("given_name"))))
                .report.decision shouldBe decision
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
        val transcript = SessionTranscript.DcApi(DCAPIHandover(DCAPIHandover.TYPE_DCAPI, ByteArray(32)))
        val otherTranscript = SessionTranscript.DcApi(DCAPIHandover(DCAPIHandover.TYPE_DCAPI, ByteArray(32) { 1 }))
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
                identifier.shouldNotBeNull().identifier shouldBe fixture.wrpIdentifier
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

    "a device request of a reader without WRPRCs and WRPAC is accepted, if registration certificates are optional" {
        // e.g. the wallet app of another wallet provider, whose reader certificate carries no WRPAC identifier
        val fixture = buildWrpFixture(wrpacIdentifier = null)
        val transcript = nfcTranscript()
        val deviceRequest = fixture.isoRequest(mdocDocRequest(), transcript).parameters.isoMdocRequest.deviceRequest

        fixture.validator().validate(deviceRequest, transcript, optionalRegistration).apply {
            report.decision shouldBe ACCEPTED
            report.checks.shouldBeInstanceOf<RelyingPartyChecks>().registration shouldBe CheckOutcome.NotApplicable
            relyingParty.shouldNotBeNull().apply {
                identifier.shouldBeNull()
                registrationCertificates.shouldBeEmpty()
                accessCertificateChain.first().encodeToDer() shouldBe fixture.wrpacChain.first().encodeToDer()
            }
        }
        fixture.validator().validate(deviceRequest, transcript, policy).apply {
            report.decision shouldBe REJECTED
            accessChecks().parsing.shouldBeInstanceOf<CheckOutcome.Failed>()
            report.checks.shouldBeInstanceOf<RelyingPartyChecks>().registration
                .shouldBeInstanceOf<CheckOutcome.Failed>().throwable
                .shouldBeInstanceOf<MissingRegistrationCertificateException>()
        }
    }

    "a WRPRC is validated, also if registration certificates are optional" {
        val fixture = buildWrpFixture()
        val transcript = nfcTranscript()
        val docRequest = fixture.docRequestWithWrprc(payload = buildWrpPayload("LEIXG-ANOTHER-RELYING-PARTY"))
        val deviceRequest = fixture.isoRequest(docRequest, transcript).parameters.isoMdocRequest.deviceRequest

        fixture.validator().validate(deviceRequest, transcript, optionalRegistration).apply {
            report.decision shouldBe REJECTED
            registrationChecks().linkage.shouldBeInstanceOf<CheckOutcome.Failed>()
        }
    }

    "a device request authenticating only some of its document requests fails its request data, not the signature" {
        val fixture = buildWrpFixture()
        val transcript = nfcTranscript()
        val first = fixture.docRequestWithWrprc().let { it.copy(readerAuth = fixture.readerAuth(it, transcript)) }
        val second = fixture.docRequestWithWrprc(claimNames = listOf("given_name"))
        val partly = DeviceRequest(Version(1, 1), docRequests = arrayOf(first, second))

        fixture.validator().validate(partly, transcript, policy).apply {
            report.decision shouldBe REJECTED
            accessChecks().signature shouldBe CheckOutcome.Passed
            report.checks.shouldBeInstanceOf<RelyingPartyChecks>().requestData
                .shouldBeInstanceOf<CheckOutcome.Failed>().throwable.shouldBeInstanceOf<UnsupportedWrpRequestException>()
        }
        val completely = partly.copy(
            docRequests = arrayOf(first, second.copy(readerAuth = fixture.readerAuth(second, transcript)))
        )
        fixture.validator().validate(completely, transcript, policy).report.decision shouldBe ACCEPTED
    }

    "of several readerAuthAll signatures, the one of a trusted WRPAC linking to the WRPRCs is selected" {
        val fixture = buildWrpFixture()
        val other = buildWrpFixture()
        val untrusted = EphemeralKeyWithSelfSignedCert()
        val transcript = nfcTranscript()
        val unsigned = DeviceRequest(Version(1, 1), docRequests = arrayOf(fixture.docRequestWithWrprc()))
        val deviceRequest = unsigned.copy(
            readerAuthAll = arrayOf(
                readerAuthAll(unsigned, transcript, untrusted, listOf(untrusted.getCertificate()!!)),
                // trusted, but the WRPRC is not issued to it
                readerAuthAll(unsigned, transcript, other.wrpKey, other.wrpacChain),
                readerAuthAll(unsigned, transcript, fixture.wrpKey, fixture.wrpacChain),
            )
        )
        val validator = RelyingPartyValidator(
            trust = RelyingPartyTrustAnchors(
                accessCertificates = TrustedCertificates { fixture.trustAnchors() + other.trustAnchors() },
                registrationCertificates = fixture.trustAnchors,
            ),
            statusValidator = fixture.statusValidator(),
        )

        validator.validate(deviceRequest, transcript, policy).apply {
            report.decision shouldBe ACCEPTED
            relyingParty.shouldNotBeNull().accessCertificateChain.first().encodeToDer() shouldBe
                    fixture.wrpacChain.first().encodeToDer()
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

    "a request without client_id fails its request data" {
        val fixture = buildWrpFixture()
        val parameters = fixture.parameters(buildWrpPayload(fixture.wrpIdentifier)).copy(clientId = null)

        fixture.validate(fixture.signedByWrp(parameters)).apply {
            report.decision shouldBe REJECTED
            report.checks.shouldBeInstanceOf<RelyingPartyChecks>().requestData
                .shouldBeInstanceOf<CheckOutcome.Failed>()
        }
    }

    "a request without the chain of its WRPAC fails the parsing of the WRPAC" {
        val fixture = buildWrpFixture()
        val parameters = fixture.parameters(buildWrpPayload(fixture.wrpIdentifier))
        val request = SignJwt<AuthenticationRequestParameters>(fixture.wrpKey, JwsHeaderNone())(
            type = "oauth-authz-req+jwt",
            payload = parameters,
            serializer = AuthenticationRequestParameters.serializer(),
        ).getOrThrow().let { RequestParametersFrom.Jws(jws = it.jws, parameters = parameters) }

        fixture.validate(request).apply {
            report.decision shouldBe REJECTED
            accessChecks().parsing.shouldBeInstanceOf<CheckOutcome.Failed>()
        }
    }

    "a WRPAC chain" - {
        "with an unrelated intermediate fails trust, although its leaf is issued by an anchor" {
            val ca = TestCertificateAuthority(name = CA_NAME)
            val leaf = ca.issue(subjectName = WRP_NAME)
            val unrelated = TestCertificateAuthority(name = "Unrelated CA").certificate

            buildWrpFixture().validateAccessCertificate(ca, leaf, unrelated) shouldContain "is not signed by"
        }

        "with an expired certificate fails trust" - {
            listOf(
                "provider" to listOf(true, false),
                "relying party" to listOf(false, true),
                "provider and relying party" to listOf(true, true),
            ).asData(nameFn = { "of the ${it.first}" }) test { case ->
                val providerExpired = case.second[0]
                val leafExpired = case.second[1]
                val ca = TestCertificateAuthority(name = CA_NAME)
                val providerKey = EphemeralKeyWithoutCert()
                val provider = TestCertificateAuthority(name = WRPAC_PROVIDER_NAME, key = providerKey)
                val providerCert = ca.issue(
                    subjectName = WRPAC_PROVIDER_NAME,
                    certificateAuthority = true,
                    validity = 1.days,
                    validFrom = if (providerExpired) Clock.System.now() - 2.days else Clock.System.now(),
                    key = providerKey,
                ).getCertificate().shouldNotBeNull()
                val leaf = provider.issue(
                    subjectName = WRP_NAME,
                    validity = 1.days,
                    validFrom = if (leafExpired) Clock.System.now() - 2.days else Clock.System.now(),
                )

                buildWrpFixture().validateAccessCertificate(ca, leaf, providerCert) shouldContain "Certificate is expired"
            }
        }

        "with a self-signed leaf fails trust" {
            val ca = TestCertificateAuthority(name = CA_NAME)
            val providerCert = ca.issue(subjectName = WRPAC_PROVIDER_NAME, certificateAuthority = true)
                .getCertificate().shouldNotBeNull()

            buildWrpFixture().validateAccessCertificate(ca, EphemeralKeyWithSelfSignedCert(), providerCert) shouldContain
                    "is not signed by"
        }

        // RFC 5280 section 4.2.1.9: a key whose certificate does not set cA "MUST NOT be used to verify certificate
        // signatures". Only the top of the chain is anchored, so without this an end entity certificate could vouch
        // for anything below it.
        "with a provider certificate that is not a certificate authority fails trust" {
            val ca = TestCertificateAuthority(name = CA_NAME)
            val providerKey = EphemeralKeyWithoutCert()
            val provider = TestCertificateAuthority(name = WRPAC_PROVIDER_NAME, key = providerKey)
            val providerCert = ca.issue(subjectName = WRPAC_PROVIDER_NAME, key = providerKey, certificateAuthority = false)
                .getCertificate().shouldNotBeNull()

            buildWrpFixture().validateAccessCertificate(ca, provider.issue(subjectName = WRP_NAME), providerCert) shouldContain
                    "may not issue certificates"
        }

        "with a provider of another subject name than the issuer of the leaf fails trust" {
            val ca = TestCertificateAuthority(name = CA_NAME)
            val providerKey = EphemeralKeyWithoutCert()
            val provider = TestCertificateAuthority(name = WRPAC_PROVIDER_NAME, key = providerKey)
            // a legitimate intermediate whose only defect is its name, so the linkage is why the chain is rejected
            val providerCert = ca.issue(subjectName = "Provider Wrong", key = providerKey, certificateAuthority = true)
                .getCertificate().shouldNotBeNull()

            buildWrpFixture().validateAccessCertificate(ca, provider.issue(subjectName = WRP_NAME), providerCert) shouldContain
                    "is not signed by"
        }
    }

    "a WRPRC" - {
        WrprcFormat.entries.asData(nameFn = { "as $it" }) - { format ->
            "signed under an untrusted CA fails its trust, not its signature" {
                val fixture = buildWrpFixture()
                val untrusted = TestCertificateAuthority(name = "Untrusted CA").issue(subjectName = WRPRC_PROVIDER_NAME)

                fixture.validateWrprc(format, signingKey = untrusted).apply {
                    report.decision shouldBe REJECTED
                    registrationChecks().signature shouldBe CheckOutcome.Passed
                    registrationChecks().trust.outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
                }
            }

            "signed by another key than the one of its certificate fails the signature" {
                val fixture = buildWrpFixture()
                val certificate = fixture.wrprcSigningKeyMaterial.getCertificate().shouldNotBeNull()
                val mismatched = KeyWithFixedCert(EphemeralKeyWithoutCert(), certificate)

                fixture.validateWrprc(format, signingKey = mismatched).apply {
                    report.decision shouldBe REJECTED
                    registrationChecks().signature.shouldBeInstanceOf<CheckOutcome.Failed>()
                }
            }

            "without a certificate chain fails parsing" {
                val fixture = buildWrpFixture()
                val result = when (format) {
                    WrprcFormat.JWT -> fixture.validateWrprc(format, signingKey = EphemeralKeyWithoutCert())
                    WrprcFormat.CWT -> fixture.validateWrprc(format, chainPlacement = CertificateChainPlacement.NONE)
                }

                result.report.decision shouldBe REJECTED
                result.registrationChecks().parsing.shouldBeInstanceOf<CheckOutcome.Failed>()
            }

            "without an optional claim is accepted" - {
                listOf<Pair<String, (String) -> WrpPayload>>(
                    "intendedUseId" to { buildWrpPayload(it, intendedUseId = null) },
                    "name" to { buildWrpPayload(it, name = null) },
                    "exp" to { buildWrpPayload(it, exp = null) },
                ).asData(nameFn = { it.first }) test { case ->
                    val fixture = buildWrpFixture()

                    fixture.validateWrprc(format, case.second(fixture.wrpIdentifier)).report.decision shouldBe ACCEPTED
                }
            }

            "not meeting a requirement of TS 119 475 fails parsing" - {
                listOf<Pair<String, (WrpPayload) -> WrpPayload>>(
                    "without an entitlement of A.2" to { it.copy(entitlements = listOf("https://example.com/entitlement")) },
                    "providing attestations without their entitlement" to {
                        it.copy(providesAttestations = listOf(defaultMdocCredential()))
                    },
                    "of a service provider without purpose" to { it.copy(purpose = null) },
                    "of a service provider without credentials" to { it.copy(credentials = null) },
                ).asData(nameFn = { it.first }) test { case ->
                    val fixture = buildWrpFixture()
                    val result = fixture.validateWrprc(format, case.second(buildWrpPayload(fixture.wrpIdentifier)))

                    result.report.decision shouldBe REJECTED
                    result.registrationChecks().parsing.shouldBeInstanceOf<CheckOutcome.Failed>()
                }
            }

            "with values of a claim, which are not supported, fails parsing" - {
                listOf(WrpClaimValue.Text("Alice"), WrpClaimValue.Integer(18), WrpClaimValue.Bool(true))
                    .asData() test { value ->
                        val fixture = buildWrpFixture()
                        val credential = defaultMdocCredential().copy(
                            claim = listOf(WrpClaim.named(DEFAULT_DOCTYPE, "given_name").copy(values = listOf(value)))
                        )
                        val payload = buildWrpPayload(fixture.wrpIdentifier, credentials = listOf(credential))
                        val result = fixture.validateWrprc(format, payload, claimNames = listOf("given_name"))

                        result.report.decision shouldBe REJECTED
                        result.registrationChecks().parsing.shouldBeInstanceOf<CheckOutcome.Failed>()
                    }
            }

            "valid for more than 12 months fails timeliness" {
                val fixture = buildWrpFixture()
                val now = Instant.fromEpochSeconds(Clock.System.now().epochSeconds)
                val payload = buildWrpPayload(fixture.wrpIdentifier, iat = now, exp = now + 400.days)

                fixture.validateWrprc(format, payload).registrationChecks().timeliness
                    .shouldBeInstanceOf<CheckOutcome.Failed>().throwable.shouldBeInstanceOf<TimelinessException>()
            }

            "whose status list can not be obtained is rejected, as its status is unknown" {
                val fixture = buildWrpFixture()
                val validator = RelyingPartyValidator(
                    trust = RelyingPartyTrustAnchors(
                        accessCertificates = fixture.trustAnchors,
                        registrationCertificates = fixture.trustAnchors,
                    ),
                    statusValidator = StatusValidator(
                        StatusListTokenResolver { throw IllegalStateException("status list unavailable") }
                    ),
                )

                fixture.validateWrprc(format, validator = validator).apply {
                    report.decision shouldBe REJECTED
                    registrationChecks().status.mechanisms.shouldBeSingleton().first().outcome
                        .shouldBeInstanceOf<CheckOutcome.Blocked>()
                }
            }
        }

        "as JWT of another type fails parsing" {
            val fixture = buildWrpFixture()

            fixture.validateWrprc(WrprcFormat.JWT, type = "not-rc-wrp+jwt").registrationChecks().parsing
                .shouldBeInstanceOf<CheckOutcome.Failed>()
        }

        "as CWT of another type can not be parsed, which fails the registration" {
            val fixture = buildWrpFixture()

            fixture.validateWrprc(WrprcFormat.CWT, type = "not-rc-wrp+cwt").report.checks
                .shouldBeInstanceOf<RelyingPartyChecks>().registration.shouldBeInstanceOf<CheckOutcome.Failed>()
                .throwable.shouldBeInstanceOf<InvalidRegistrationCertificateException>()
        }

        "as CWT with x5chain in the protected header is accepted" {
            val fixture = buildWrpFixture()

            fixture.validateWrprc(WrprcFormat.CWT, chainPlacement = CertificateChainPlacement.PROTECTED)
                .report.decision shouldBe ACCEPTED
        }

        "as CWT with an additional numeric path still authorizes its named claims" {
            val fixture = buildWrpFixture()
            val credential = defaultMdocCredential().let {
                it.copy(
                    claim = it.claim.orEmpty() + WrpClaim(
                        listOf(WrpClaimPathSegment.Name(DEFAULT_DOCTYPE), WrpClaimPathSegment.Index(0u))
                    )
                )
            }
            val payload = buildWrpPayload(fixture.wrpIdentifier, credentials = listOf(credential))

            fixture.validateWrprc(WrprcFormat.CWT, payload).report.decision shouldBe ACCEPTED
        }

        "as CWT does not authorize a document request for more claims than it registers" {
            val fixture = buildWrpFixture()
            val claimNames = listOf("given_name", "family_name", "birth_date", "portrait")

            fixture.validateWrprc(WrprcFormat.CWT, claimNames = claimNames).apply {
                report.decision shouldBe REJECTED
                registrationChecks().requestAuthorization.shouldBeInstanceOf<CheckOutcome.Failed>()
                    .throwable.shouldBeInstanceOf<UnregisteredRequestException>()
            }
        }

        "does not authorize a credential format it does not register" {
            val fixture = buildWrpFixture()
            val payload = buildWrpPayload(fixture.wrpIdentifier, credentials = listOf(defaultMdocCredential()))

            fixture.validateWrprc(WrprcFormat.JWT, payload, request = sdJwtDcqlRequest(vctValue = PID_VCT)).apply {
                report.decision shouldBe REJECTED
                registrationChecks().requestAuthorization.shouldBeInstanceOf<CheckOutcome.Failed>()
                    .throwable.shouldBeInstanceOf<UnregisteredRequestException>()
            }
        }

        "does not authorize an unregistered wildcard request, and names only that one" {
            val fixture = buildWrpFixture()
            val mdocQuery = (mdocDcqlRequest() as CredentialPresentationRequest.DCQLRequest)
                .dcqlQuery.credentials.single()
            val wildcardQuery = DCQLSdJwtCredentialQuery(
                id = DCQLCredentialQueryIdentifier("wildcard"),
                meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(vctValues = listOf(PID_VCT)),
                claims = DCQLClaimsQueryList(
                    nonEmptyListOf(
                        DCQLJsonClaimsQuery(
                            path = DCQLClaimsPathPointer(nonEmptyListOf(NameSegment("nationalities"), NullSegment))
                        )
                    )
                ),
            )
            val request = CredentialPresentationRequest.DCQLRequest(
                DCQLQuery(credentials = DCQLCredentialQueryList(nonEmptyListOf(mdocQuery, wildcardQuery)))
            )

            fixture.validateWrprc(WrprcFormat.JWT, request = request).registrationChecks().requestAuthorization
                .shouldBeInstanceOf<CheckOutcome.Failed>().throwable.shouldBeInstanceOf<UnregisteredRequestException>()
                .requests.shouldBeSingleton().first().first
                .shouldBeInstanceOf<WrpCredentialRequest.WrpDcqlCredentialQuery>().query.id shouldBe wildcardQuery.id
        }
    }

    "a verifier_info whose WRPRC can not be parsed fails the registration" - {
        listOf<Pair<String, suspend (WrpFixture) -> List<VerifierInfo>>>(
            "base64url-encoded, but no JWS" to {
                listOf(VerifierInfo(REGISTRATION_CERT_FORMAT, "no-jws".encodeToByteArray().encodeToString(Base64UrlStrict)))
            },
            "next to another format" to {
                listOf(VerifierInfo("other-format", "ignored"), VerifierInfo(REGISTRATION_CERT_FORMAT, "not-a-jws"))
            },
            "given as a JSON object" to {
                listOf(VerifierInfo(REGISTRATION_CERT_FORMAT, buildJsonObject { put("jwt", "not-a-string-wrprc") }))
            },
            "next to a valid one" to {
                listOf(
                    VerifierInfo(REGISTRATION_CERT_FORMAT, "not-a-jws"),
                    VerifierInfo(
                        REGISTRATION_CERT_FORMAT,
                        signWrprc(it.wrprcSigningKeyMaterial, buildWrpPayload(it.wrpIdentifier)),
                    ),
                )
            },
        ).asData(nameFn = { it.first }) test { case ->
            val fixture = buildWrpFixture()
            val parameters = fixture.parameters(buildWrpPayload(fixture.wrpIdentifier))
                .copy(verifierInfo = case.second(fixture).toNonEmptyList())

            fixture.validate(fixture.signedByWrp(parameters)).report.checks.shouldBeInstanceOf<RelyingPartyChecks>()
                .registration.shouldBeInstanceOf<CheckOutcome.Failed>().throwable
                .shouldBeInstanceOf<InvalidRegistrationCertificateException>()
        }
    }

    "a verifier_info of another format only has no WRPRC" {
        val fixture = buildWrpFixture()
        val parameters = fixture.parameters(buildWrpPayload(fixture.wrpIdentifier))
            .copy(verifierInfo = nonEmptyListOf(VerifierInfo("other-format", "ignored")))

        fixture.validate(fixture.signedByWrp(parameters)).report.checks.shouldBeInstanceOf<RelyingPartyChecks>()
            .registration.shouldBeInstanceOf<CheckOutcome.Failed>().throwable
            .shouldBeInstanceOf<MissingRegistrationCertificateException>()
    }

    "a device request" - {
        "with a WRPRC that can not be parsed fails the registration" {
            val fixture = buildWrpFixture()
            val transcript = nfcTranscript()
            val docRequest = mdocDocRequest().withEuWrprc(byteArrayOf(1, 2, 3))
            val deviceRequest = fixture.isoRequest(docRequest, transcript).parameters.isoMdocRequest.deviceRequest

            fixture.validator().validate(deviceRequest, transcript, policy).report.checks
                .shouldBeInstanceOf<RelyingPartyChecks>().registration.shouldBeInstanceOf<CheckOutcome.Failed>()
                .throwable.shouldBeInstanceOf<InvalidRegistrationCertificateException>().cause.shouldNotBeNull()
        }

        "with a WRPRC in only some of its document requests fails the registration" {
            val fixture = buildWrpFixture()
            val transcript = nfcTranscript()
            val deviceRequest = fixture.isoRequest(
                fixture.docRequestWithWrprc(),
                transcript,
                mdocDocRequest(doctypeValue = "org.iso.18013.5.1.mDL"),
            ).parameters.isoMdocRequest.deviceRequest

            fixture.validator().validate(deviceRequest, transcript, policy).report.checks
                .shouldBeInstanceOf<RelyingPartyChecks>().registration.shouldBeInstanceOf<CheckOutcome.Failed>()
                .throwable.shouldBeInstanceOf<InvalidRegistrationCertificateException>()
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

/** Accepts a relying party without WRPRCs, e.g. a reader outside of the EUDI Wallet ecosystem. */
private val optionalRegistration = policy.copy(registration = RegistrationPolicy.ValidateIfPresent)

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

private const val RELYING_PARTY = "LEIXG-RELYING-PARTY"
private const val INTERMEDIARY = "LEIXG-INTERMEDIARY"

/** A WRPRC of [RELYING_PARTY] acting through [intermediary] (ETSI TS 119 475 V1.2.1, 4.5, Table 10). */
private fun intermediatedPayload(intermediary: String = INTERMEDIARY) =
    buildWrpPayload(RELYING_PARTY).copy(intermediary = WrpIntermediary(sub = intermediary))

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
private fun nfcTranscript(handoverSelect: ByteArray = byteArrayOf(1)) = SessionTranscript.Nfc(
    deviceEngagementBytes = byteArrayOf(0x0a),
    eReaderKeyBytes = byteArrayOf(0x0b),
    handover = NFCHandover(handoverSelect = handoverSelect, handoverRequest = null),
)

/** A document request carrying the WRPRC of the relying party in `euWrprc`. */
private suspend fun WrpFixture.docRequestWithWrprc(
    claimNames: List<String> = listOf("given_name", "family_name", "birth_date"),
    payload: WrpPayload = buildWrpPayload(wrpIdentifier),
): DocRequest {
    val wrprc = coseCompliantSerializer.encodeToByteArray(signWrprcCose(wrprcSigningKeyMaterial, payload))
    return mdocDocRequest(claimNames = claimNames).withEuWrprc(wrprc)
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
    vararg otherDocRequests: DocRequest,
    signingKey: KeyMaterial = wrpKey,
): RequestParametersFrom.IsoMdocDcApi {
    val unsigned = DeviceRequest(Version(1, 1), docRequests = arrayOf(docRequest, *otherDocRequests))
    val readerAuth = readerAuthAll(unsigned, transcript, signingKey, wrpacChain)
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

/** A `readerAuthAll` signature over [unsigned] and [transcript] by [key], with [chain] in its `x5chain`. */
private suspend fun readerAuthAll(
    unsigned: DeviceRequest,
    transcript: SessionTranscript,
    key: KeyMaterial,
    chain: List<X509Certificate>,
): CoseSigned<ByteArray> = signDetached(key, chain, ReaderAuthenticationAll.detachedPayload(unsigned, transcript))

/** The `readerAuth` of [docRequest] over [transcript] by the WRPAC. */
private suspend fun WrpFixture.readerAuth(docRequest: DocRequest, transcript: SessionTranscript) =
    signDetached(wrpKey, wrpacChain, ReaderAuthentication.detachedPayload(docRequest, transcript))

private suspend fun signDetached(key: KeyMaterial, chain: List<X509Certificate>, payload: ByteArray) =
    SignCoseDetached<ByteArray>(
        key,
        unprotectedHeaderModifier = { header, _ -> header?.copy(certificateChain = chain.map { it.encodeToDer() }) },
    )(
        protectedHeader = null,
        unprotectedHeader = CoseHeader(),
        payload = payload,
        serializer = ByteArraySerializer(),
    ).getOrThrow()

/** The transport of a WRPRC: a JWT in `verifier_info` of an authorization request, a CWT in `euWrprc` of an mdoc request. */
private enum class WrprcFormat { JWT, CWT }

/**
 * Validates a request of this relying party with [payload] as its WRPRC in [format], signed by [signingKey]: a JWT in
 * an authorization request for [request], a CWT in a proximity device request for the mdoc claims [claimNames].
 */
private suspend fun WrpFixture.validateWrprc(
    format: WrprcFormat,
    payload: WrpPayload = buildWrpPayload(wrpIdentifier),
    signingKey: KeyMaterial = wrprcSigningKeyMaterial,
    type: String = when (format) {
        WrprcFormat.JWT -> WRPRC_JWS_TYPE
        WrprcFormat.CWT -> WRPRC_CWT_TYPE
    },
    chainPlacement: CertificateChainPlacement = CertificateChainPlacement.UNPROTECTED,
    claimNames: List<String> = listOf("given_name", "family_name", "birth_date"),
    request: CredentialPresentationRequest = mdocDcqlRequest(claimNames = claimNames),
    validator: RelyingPartyValidator = validator(),
): RelyingPartyValidationResult = when (format) {
    WrprcFormat.JWT -> validator.validate(
        signedByWrp(
            AuthenticationRequestParameters(
                clientId = clientId,
                verifierInfo = nonEmptyListOf(
                    VerifierInfo(REGISTRATION_CERT_FORMAT, signWrprc(signingKey, payload, type))
                ),
                dcqlQuery = (request as CredentialPresentationRequest.DCQLRequest).dcqlQuery,
            )
        ),
        policy,
    )

    WrprcFormat.CWT -> {
        val transcript = nfcTranscript()
        val wrprc = signWrprcCose(signingKey, payload, type, chainPlacement)
        val docRequest = mdocDocRequest(claimNames = claimNames)
            .withEuWrprc(coseCompliantSerializer.encodeToByteArray(wrprc))
        validator.validate(isoRequest(docRequest, transcript).parameters.isoMdocRequest.deviceRequest, transcript, policy)
    }
}

/**
 * Validates a request signed by [leaf], the key of the WRPAC, transporting [leaf] and [intermediates] as the chain of
 * the WRPAC, with [anchor] as the anchor of WRPACs, returning why its trust failed.
 */
private suspend fun WrpFixture.validateAccessCertificate(
    anchor: TestCertificateAuthority,
    leaf: KeyMaterial,
    vararg intermediates: X509Certificate,
): String {
    val chain = listOf(leaf.getCertificate().shouldNotBeNull(), *intermediates)
    val fixture = copy(
        trustAnchors = TrustedCertificates { setOf(anchor.certificate) },
        wrpacChain = chain,
        wrpKey = leaf,
        clientId = "x509_hash:${chain.first().encodeToDer().sha256().encodeToString(Base64UrlStrict)}",
    )
    val result = fixture.validate(fixture.request(buildWrpPayload(wrpIdentifier)))

    result.report.decision shouldBe REJECTED
    return result.accessChecks().trust.outcome.shouldBeInstanceOf<CheckOutcome.Failed>().throwable.message.shouldNotBeNull()
}

private fun DocRequest.withEuWrprc(euWrprc: ByteArray) =
    copy(itemsRequest = ByteStringWrapper(itemsRequest.value.copy(requestInfo = DocRequestInfo(euWrprc = euWrprc))))

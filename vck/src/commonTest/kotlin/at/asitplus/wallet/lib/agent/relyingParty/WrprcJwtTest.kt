package at.asitplus.wallet.lib.agent.relyingParty

import at.asitplus.KmmResult
import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.etsi.relyingParty.WrpClaim
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NameSegment
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NullSegment
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyWithFixedCert
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolverImpl
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpAccessCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpChainValidator
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRegistrationCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRequestData
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrpCredentialRequest
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrprcValidationResult
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrprcValidator
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.isValid
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlin.time.Clock.System
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@OptIn(ExperimentalUuidApi::class)
val WrprcJwtTest by matrixSuite {

    "Issuance and validation round-trip" {
        val fixture = buildWrpFixture()

        WrpChainValidator(
            chain = fixture.wrpacChain,
            certificateTrustAnchors = fixture.trustAnchors,
        ).getOrThrow() shouldBe true

        val wrpacValidation = fixture.validateWrpac().getOrThrow()
        wrpacValidation.identifierResult?.identifier shouldBe fixture.wrpIdentifier

        val result =
            fixture.validateWrprc(payload = buildWrpPayload(fixture.wrpIdentifier)).getOrThrow()

        result.certificateValidationResults.values.all { it.getOrNull()?.isValid() == true } shouldBe true
        result.requestDataValidationResults.toMap().values.all { it.getOrThrow().isValid() } shouldBe true
    }

    "WRPRC validation with no registration certificate present succeeds with empty results" {
        val fixture = buildWrpFixture()
        val wrpacValidation = fixture.validateWrpac().getOrThrow()

        val result = WrprcValidator()(
            identifierResult = wrpacValidation.identifierResult,
            validationData = WrpRequestData(
                clientId = fixture.clientId,
                accessCertificate = WrpAccessCertificate(fixture.wrpacChain),
                registrationCertificate = emptyMap(),
            ),
            tokenStatusResolver = TokenStatusResolverImpl({ statusListUrl ->
                buildStatusListToken(statusListUrl, revokedIndex = 1)
            }),
            certificateTrustAnchors = fixture.trustAnchors,
        )

        result.exceptionOrNull().shouldNotBeNull().message.shouldContain("No registration certificates to verify")
    }

    "Wrong JWS header type fails" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            jwsType = "not-rc-wrp+jwt",
        )

        result.getOrThrow().certificateValidationResults.values.single().getOrThrow().validHeader shouldBe false
    }

    "WRPRC signed under an untrusted CA fails chain validation" {
        val fixture = buildWrpFixture()
        val untrustedSigner = TestCertificateAuthority(name = "Untrusted CA").issue(subjectName = WRPRC_PROVIDER_NAME)

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            signingKeyMaterial = untrustedSigner,
        ).getOrThrow()

        val validation = result.certificateValidationResults.values.single().getOrThrow()
        validation.validChain shouldBe false
        validation.validSignature shouldBe true
    }

    "Status list of a WRPRC from an untrusted registrar is not fetched" {
        val fixture = buildWrpFixture()
        val untrustedSigner = TestCertificateAuthority(name = "Untrusted CA").issue(subjectName = WRPRC_PROVIDER_NAME)
        val fetched = mutableListOf<Any>()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            signingKeyMaterial = untrustedSigner,
            tokenStatusResolver = TokenStatusResolverImpl(StatusListTokenResolver { statusListUrl ->
                fetched += statusListUrl
                buildStatusListToken(statusListUrl, revokedIndex = 1)
            }),
        ).getOrThrow()

        result.certificateValidationResults.values.single().getOrThrow().apply {
            validStatusList shouldBe false
            tokenStatus.exceptionOrNull().shouldNotBeNull().message.shouldContain("not trusted")
        }
        fetched shouldBe emptyList()
    }

    "Status list of a WRPRC with a signature from a non-matching key is not fetched" {
        val fixture = buildWrpFixture()
        val realCertificate = fixture.wrprcSigningKeyMaterial.getCertificate().shouldNotBeNull()
        val fetched = mutableListOf<Any>()

        fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            signingKeyMaterial = KeyWithFixedCert(EphemeralKeyWithoutCert(), realCertificate),
            tokenStatusResolver = TokenStatusResolverImpl(StatusListTokenResolver { statusListUrl ->
                fetched += statusListUrl
                buildStatusListToken(statusListUrl, revokedIndex = 1)
            }),
        ).getOrThrow()

        fetched shouldBe emptyList()
    }

    "Signature from a non-matching key fails" {
        val fixture = buildWrpFixture()
        val realCertificate = fixture.wrprcSigningKeyMaterial.getCertificate().shouldNotBeNull()
        val mismatchedSigner = KeyWithFixedCert(EphemeralKeyWithoutCert(), realCertificate)

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            signingKeyMaterial = mismatchedSigner,
        )

        result.getOrThrow().certificateValidationResults.values.single().getOrThrow().validSignature shouldBe false
    }

    "Expired WRPRC payload fails payload validation" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(
            fixture.wrpIdentifier,
            iat = Instant.fromEpochSeconds((System.now() - 60.days).epochSeconds),
            exp = Instant.fromEpochSeconds((System.now() - 30.days).epochSeconds),
        )

        val result = fixture.validateWrprc(payload = payload)
        result.getOrThrow().certificateValidationResults.values.single().getOrThrow().validPayload shouldBe false
    }

    "WRPRC payload missing optional intendedUseId still validates" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(fixture.wrpIdentifier, intendedUseId = null)

        val result = fixture.validateWrprc(payload = payload)
        result.isSuccess.shouldBe(true)
    }

    "WRPRC payload missing optional exp still validates" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(fixture.wrpIdentifier, exp = null)

        val result = fixture.validateWrprc(payload = payload)
        result.isSuccess.shouldBe(true)

    }

    "WRPRC payload with exp more than 12 months after iat fails payload validation" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(
            fixture.wrpIdentifier,
            iat = Instant.fromEpochSeconds(System.now().epochSeconds),
            exp = Instant.fromEpochSeconds((System.now() + 400.days).epochSeconds),
        )

        val result = fixture.validateWrprc(payload = payload)

        result.getOrThrow().certificateValidationResults.values.single().getOrThrow().validPayload shouldBe false
    }

    "sub not matching the WRPAC identifier fails linkage validation" {
        val fixture = buildWrpFixture(wrpIdentifier = "WRP-${Uuid.generateV4()}")
        val payload = buildWrpPayload(wrpIdentifier = "WRP-${Uuid.generateV4()}")

        val result = fixture.validateWrprc(payload = payload).getOrThrow()

        result.certificateValidationResults.all { it.value.getOrNull()?.validLinkage == false }.shouldBe(true)
    }

    "Revoked status list entry fails status validation only" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(fixture.wrpIdentifier, statusListIdx = 0)

        val result = fixture.validateWrprc(payload = payload, revokedStatusIndex = 0).getOrThrow()
        result.certificateValidationResults.all { it.value.getOrNull()?.validStatusList == false }.shouldBe(true)
        result.certificateValidationResults.values.single().getOrThrow().tokenStatus.getOrThrow() shouldBe
                TokenStatus.Invalid
    }

    "Requesting more attributes than the WRPRC declares fails request validation (over-asking)" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            request = mdocDcqlRequest(claimNames = listOf("given_name", "family_name", "birth_date", "portrait")),
        ).getOrThrow()

        result.certificateValidationResults.values.all { it.getOrNull()?.isValid() == true } shouldBe true
        result.requestDataValidationResults.toMap().values.single().getOrThrow().isValid() shouldBe false
    }

    "Requesting a credential format the WRPRC never declared finds no match" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(
                wrpIdentifier = fixture.wrpIdentifier,
                credentials = listOf(defaultMdocCredential())
            ),
            request = sdJwtDcqlRequest(vctValue = "urn:eudi:pid:1"),
        ).getOrThrow()

        result.requestDataValidationResults.toMap().values.single().getOrThrow().credentialTypeValidity.shouldBe(false)
    }

    "Requesting only claims the WRPRC actually declares still validates" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            request = mdocDcqlRequest(claimNames = listOf("given_name")),
        ).getOrThrow()

        result.requestDataValidationResults.toMap().values.single().getOrThrow().isValid() shouldBe true
    }

    "WRPRC with unsupported claim values does not authorize a path-only request" {
        val fixture = buildWrpFixture()
        val credential = defaultMdocCredential().copy(
            claim = listOf(WrpClaim(path = listOf(DEFAULT_DOCTYPE, "given_name"), values = listOf("Alice")))
        )

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier, credentials = listOf(credential)),
            request = mdocDcqlRequest(claimNames = listOf("given_name")),
        )

        result.getOrThrow().certificateValidationResults.values.single().getOrThrow().validPayload shouldBe false
    }

    "JWT without a certificate chain is invalid and carries the cause" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            signingKeyMaterial = EphemeralKeyWithoutCert(),
        ).getOrThrow()

        result.certificateValidationResults.values.single().exceptionOrNull().shouldNotBeNull()
            .message.shouldContain("Certificate chain is empty")
    }

    "Credential request that can not be validated is invalid and does not affect other requests" {
        val fixture = buildWrpFixture()
        val mdocQuery = (mdocDcqlRequest() as CredentialPresentationRequest.DCQLRequest)
            .dcqlQuery.credentials.single()
        val nullSegmentQuery = DCQLSdJwtCredentialQuery(
            id = DCQLCredentialQueryIdentifier("null-segment"),
            meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(vctValues = listOf("urn:eudi:pid:1")),
            claims = DCQLClaimsQueryList(
                nonEmptyListOf(
                    DCQLJsonClaimsQuery(
                        path = DCQLClaimsPathPointer(nonEmptyListOf(NameSegment("nationalities"), NullSegment))
                    )
                )
            ),
        )
        val request = CredentialPresentationRequest.DCQLRequest(
            DCQLQuery(credentials = DCQLCredentialQueryList(nonEmptyListOf(mdocQuery, nullSegmentQuery)))
        )

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            request = request,
        ).getOrThrow()

        result.certificateValidationResults.values.single().getOrThrow().isValid() shouldBe true
        val requestResults = result.requestDataValidationResults.associate { (request, result) ->
            (request as WrpCredentialRequest.WrpDcqlCredentialQuery).query.id to result
        }
        requestResults.getValue(mdocQuery.id).getOrThrow().isValid() shouldBe true
        requestResults.getValue(nullSegmentQuery.id).exceptionOrNull().shouldNotBeNull()
            .message.shouldContain("NullSegment")
        @Suppress("DEPRECATION")
        result.requestDataValidation.associate { (request, validity) ->
            (request as WrpCredentialRequest.WrpDcqlCredentialQuery).query.id to validity.isValid()
        } shouldBe mapOf(mdocQuery.id to true, nullSegmentQuery.id to false)
    }

    "Deprecated constructor maps a missing certificate validation to a failure" {
        val fixture = buildWrpFixture()
        val wrprcJws = signWrprc(fixture.wrprcSigningKeyMaterial, buildWrpPayload(fixture.wrpIdentifier))
        val certificate = WrpRegistrationCertificate.WrpJwtRegistrationCertificate(JwsCompactTyped<WrpPayload>(wrprcJws))

        @Suppress("DEPRECATION")
        val result = WrprcValidationResult(
            certificateValidation = mapOf(certificate to null),
            requestDataValidation = emptyList(),
        )

        result.certificateValidationResults.getValue(certificate).isFailure shouldBe true
        result.requestDataValidationResults shouldBe emptyList()
    }

    "Status list that can not be obtained is invalid and carries the cause" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            tokenStatusResolver = { KmmResult.failure(IllegalStateException("status list unavailable")) },
        ).getOrThrow()

        val validation = result.certificateValidationResults.values.single().getOrThrow()
        validation.validStatusList shouldBe false
        validation.tokenStatus.exceptionOrNull().shouldNotBeNull().message shouldBe "status list unavailable"
    }
}

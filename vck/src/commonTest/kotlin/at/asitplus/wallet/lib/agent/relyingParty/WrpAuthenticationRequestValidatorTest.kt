package at.asitplus.wallet.lib.agent.relyingParty

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.request.IsoMdocRequest
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
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.validation.relyingParty.InvalidRegistrationCertificateException
import at.asitplus.wallet.lib.agent.validation.relyingParty.MissingRegistrationCertificateException
import at.asitplus.wallet.lib.agent.validation.relyingParty.UnsupportedWrpRequestException
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpAuthenticationRequestValidator
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRegistrationCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrpCredentialRequest
import at.asitplus.wallet.lib.cbor.CoseHeaderCertificate
import at.asitplus.wallet.lib.cbor.SignCoseDetached
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import io.github.z4kn4fein.semver.Version
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.encodeToByteArray

val WrpAuthenticationRequestValidatorTest by matrixSuite {
    "signed request is parsed into WRP validation data" {
        val fixture = buildWrpFixture()
        val wrprcPayload = buildWrpPayload(fixture.wrpIdentifier)
        val wrprcJws = signWrprc(fixture.wrprcSigningKeyMaterial, wrprcPayload)
        val dcql = (mdocDcqlRequest() as CredentialPresentationRequest.DCQLRequest).dcqlQuery
        val parameters = AuthenticationRequestParameters(
            clientId = fixture.clientId,
            verifierInfo = nonEmptyListOf(VerifierInfo(REGISTRATION_CERT_FORMAT, wrprcJws)),
            dcqlQuery = dcql,
        )
        val signedRequest = SignJwt<AuthenticationRequestParameters>(
            fixture.wrprcSigningKeyMaterial,
            JwsHeaderCertOrJwk(),
        )(type = "oauth-authz-req+jwt", payload = parameters, serializer = AuthenticationRequestParameters.serializer())
            .getOrThrow()

        val data = WrpAuthenticationRequestValidator(
            RequestParametersFrom.Jws(jws = signedRequest.jws, parameters = parameters)
        ).getOrThrow()

        data.clientId shouldBe fixture.clientId
        data.accessCertificate.certificateChain shouldBe signedRequest.jws.jwsHeader.certificateChain
        val (certificate, requests) = data.registrationCertificate.entries.single()
        certificate.shouldBeInstanceOf<WrpRegistrationCertificate.WrpJwtRegistrationCertificate>()
            .payload shouldBe wrprcPayload
        requests.single().shouldBeInstanceOf<WrpCredentialRequest.WrpDcqlCredentialQuery>()
            .query shouldBe dcql.credentials.single()
    }

    "signed request with an unparseable WRPRC fails with the parsing error as cause" {
        val fixture = buildWrpFixture()
        val parameters = AuthenticationRequestParameters(
            clientId = fixture.clientId,
            verifierInfo = nonEmptyListOf(
                VerifierInfo("other-format", "ignored"),
                VerifierInfo(REGISTRATION_CERT_FORMAT, "not-a-jws"),
            ),
            dcqlQuery = (mdocDcqlRequest() as CredentialPresentationRequest.DCQLRequest).dcqlQuery,
        )

        val failure = WrpAuthenticationRequestValidator(fixture.signedRequest(parameters)).exceptionOrNull()

        failure.shouldBeInstanceOf<InvalidRegistrationCertificateException>().cause.shouldNotBeNull()
    }

    "signed request with one valid and one unparseable WRPRC is rejected" {
        val fixture = buildWrpFixture()
        val wrprcJws = signWrprc(fixture.wrprcSigningKeyMaterial, buildWrpPayload(fixture.wrpIdentifier))
        val parameters = AuthenticationRequestParameters(
            clientId = fixture.clientId,
            verifierInfo = nonEmptyListOf(
                VerifierInfo(REGISTRATION_CERT_FORMAT, "not-a-jws"),
                VerifierInfo(REGISTRATION_CERT_FORMAT, wrprcJws),
            ),
            dcqlQuery = (mdocDcqlRequest() as CredentialPresentationRequest.DCQLRequest).dcqlQuery,
        )

        val failure = WrpAuthenticationRequestValidator(fixture.signedRequest(parameters)).exceptionOrNull()

        failure.shouldBeInstanceOf<InvalidRegistrationCertificateException>().message shouldContain "contains 2"
    }

    "signed request without a WRPRC fails as missing" {
        val fixture = buildWrpFixture()
        val dcqlQuery = (mdocDcqlRequest() as CredentialPresentationRequest.DCQLRequest).dcqlQuery
        val withoutVerifierInfo = AuthenticationRequestParameters(clientId = fixture.clientId, dcqlQuery = dcqlQuery)
        val withOtherVerifierInfo = withoutVerifierInfo.copy(
            verifierInfo = nonEmptyListOf(VerifierInfo("other-format", "ignored"))
        )

        listOf(withoutVerifierInfo, withOtherVerifierInfo).forEach {
            WrpAuthenticationRequestValidator(fixture.signedRequest(it)).exceptionOrNull()
                .shouldBeInstanceOf<MissingRegistrationCertificateException>()
        }
    }

    "unsigned request is not supported" {
        val parameters = AuthenticationRequestParameters(nonce = "nonce")

        WrpAuthenticationRequestValidator(
            RequestParametersFrom.Json(jsonString = "", parameters = parameters)
        ).exceptionOrNull().shouldBeInstanceOf<UnsupportedWrpRequestException>()
    }

    "ISO request without any WRPRC fails as missing" {
        val (isoRequest, transcript) = isoRequest(mdocDocRequest())

        WrpAuthenticationRequestValidator(isoRequest, transcript).exceptionOrNull()
            .shouldBeInstanceOf<MissingRegistrationCertificateException>()
    }

    "ISO request without any WRPRC fails as missing, even without reader authentication" {
        val (isoRequest, transcript) = isoRequest(mdocDocRequest())
        val unauthenticated = isoRequest.copy(
            parameters = RequestParametersFrom.IsoMdocDcApi.IsoMdocRequestWrapper(
                isoRequest.parameters.isoMdocRequest.copy(
                    deviceRequest = isoRequest.parameters.isoMdocRequest.deviceRequest.copy(readerAuthAll = null)
                )
            )
        )

        WrpAuthenticationRequestValidator(unauthenticated, transcript).exceptionOrNull()
            .shouldBeInstanceOf<MissingRegistrationCertificateException>()
    }

    "ISO request with an unparseable WRPRC fails with the parsing error as cause" {
        val (isoRequest, transcript) = isoRequest(mdocDocRequest().withEuWrprc(byteArrayOf(1, 2, 3)))

        WrpAuthenticationRequestValidator(isoRequest, transcript).exceptionOrNull()
            .shouldBeInstanceOf<InvalidRegistrationCertificateException>().cause.shouldNotBeNull()
    }

    "ISO request with a WRPRC in only some document requests is rejected" {
        val fixture = buildWrpFixture()
        val wrprc = signWrprcCose(fixture.wrprcSigningKeyMaterial, buildWrpPayload(fixture.wrpIdentifier))
        val (isoRequest, transcript) = isoRequest(
            mdocDocRequest().withEuWrprc(coseCompliantSerializer.encodeToByteArray(wrprc)),
            mdocDocRequest(doctypeValue = "org.iso.18013.5.1.mDL"),
        )

        WrpAuthenticationRequestValidator(isoRequest, transcript).exceptionOrNull()
            .shouldBeInstanceOf<InvalidRegistrationCertificateException>()
    }

    "ISO request accepts only a WRPAC that signed its document request" {
        val fixture = buildWrpFixture()
        val wrpacSigner = EphemeralKeyWithSelfSignedCert()
        val wrprc = signWrprcCose(fixture.wrprcSigningKeyMaterial, buildWrpPayload(fixture.wrpIdentifier))
        val (isoRequest, transcript) = isoRequest(
            mdocDocRequest().withEuWrprc(coseCompliantSerializer.encodeToByteArray(wrprc)),
            wrpacSigner = wrpacSigner,
        )

        val result = WrpAuthenticationRequestValidator(isoRequest, transcript).getOrThrow()
        result.accessCertificate.certificateChain!!.first().encodeToDer() shouldBe wrpacSigner.getCertificate()!!
            .encodeToDer()
        WrpAuthenticationRequestValidator(isoRequest).isFailure shouldBe true
    }
}

private suspend fun WrpFixture.signedRequest(parameters: AuthenticationRequestParameters) =
    SignJwt<AuthenticationRequestParameters>(wrprcSigningKeyMaterial, JwsHeaderCertOrJwk())(
        type = "oauth-authz-req+jwt",
        payload = parameters,
        serializer = AuthenticationRequestParameters.serializer(),
    ).getOrThrow().let { RequestParametersFrom.Jws(jws = it.jws, parameters = parameters) }

private fun DocRequest.withEuWrprc(euWrprc: ByteArray) =
    copy(itemsRequest = ByteStringWrapper(itemsRequest.value.copy(requestInfo = DocRequestInfo(euWrprc = euWrprc))))

/** ISO DC API request whose document requests are signed by [wrpacSigner] with `readerAuthAll`. */
private suspend fun isoRequest(
    vararg docRequests: DocRequest,
    wrpacSigner: KeyMaterial = EphemeralKeyWithSelfSignedCert(),
): Pair<RequestParametersFrom.IsoMdocDcApi, SessionTranscript> {
    val transcript = SessionTranscript.forDcApi(DCAPIHandover(DCAPIHandover.TYPE_DCAPI, ByteArray(32)))
    val unsigned = DeviceRequest(Version(1, 1), docRequests = arrayOf(*docRequests))
    val readerAuth = SignCoseDetached<ByteArray>(
        wrpacSigner, unprotectedHeaderModifier = CoseHeaderCertificate()
    )(
        protectedHeader = null,
        unprotectedHeader = CoseHeader(),
        payload = ReaderAuthenticationAll.detachedPayload(unsigned, transcript),
        serializer = ByteArraySerializer(),
    ).getOrThrow()
    val deviceRequest = DeviceRequest(
        parsedVersion = Version(1, 1),
        docRequests = arrayOf(*docRequests),
        readerAuthAll = arrayOf(readerAuth)
    )
    val isoRequest = RequestParametersFrom.IsoMdocDcApi(
        parameters = RequestParametersFrom.IsoMdocDcApi.IsoMdocRequestWrapper(
            IsoMdocRequest(
                deviceRequest,
                EncryptionInfo(
                    "dcapi",
                    EncryptionParameters(recipientPublicKey = wrpacSigner.publicKey.toCoseKey().getOrThrow())
                ),
            )
        ),
        jsonString = "",
        callingOrigin = "https://example.com",
    )
    return isoRequest to transcript
}

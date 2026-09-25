package at.asitplus.wallet.lib.agent.relyingParty

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.request.IsoMdocRequest
import at.asitplus.iso.DeviceRequest
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
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpAuthenticationRequestValidator
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRegistrationCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrpCredentialRequest
import at.asitplus.wallet.lib.cbor.CoseHeaderCertificate
import at.asitplus.wallet.lib.cbor.SignCoseDetached
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import io.github.z4kn4fein.semver.Version
import io.kotest.matchers.shouldBe
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

    "ISO request accepts only a WRPAC that signed its document request" {
        val fixture = buildWrpFixture()
        val wrpacSigner = EphemeralKeyWithSelfSignedCert()
        val wrprc = signWrprcCose(fixture.wrprcSigningKeyMaterial, buildWrpPayload(fixture.wrpIdentifier))
        val item = mdocDocRequest().itemsRequest.value.copy(
            requestInfo = DocRequestInfo(euWrprc = coseCompliantSerializer.encodeToByteArray(wrprc))
        )
        val doc = mdocDocRequest().copy(itemsRequest = ByteStringWrapper(item))
        val transcript = SessionTranscript.forDcApi(DCAPIHandover(DCAPIHandover.TYPE_DCAPI, ByteArray(32)))
        val unsigned = DeviceRequest(Version(1, 1), docRequests = arrayOf(doc))
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
            docRequests = arrayOf(doc),
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

        val result = WrpAuthenticationRequestValidator(isoRequest, transcript).getOrThrow()
        result.accessCertificate.certificateChain!!.first().encodeToDer() shouldBe wrpacSigner.getCertificate()!!
            .encodeToDer()
        WrpAuthenticationRequestValidator(isoRequest).isFailure shouldBe true
    }
}

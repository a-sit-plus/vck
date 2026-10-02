package at.asitplus.wallet.lib.openid

import at.asitplus.dcapi.request.verifier.DigitalCredentialGetRequest
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.etsi.relyingParty.WrpStatus
import at.asitplus.etsi.relyingParty.WrpStatusList
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.VerifierInfo.REGISTRATION_CERT_FORMAT
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.VerifierInfo
import at.asitplus.signum.indispensable.josef.JwsGeneral
import at.asitplus.signum.indispensable.josef.typed
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRegistrationCertificate
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.utils.DefaultMapStore
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Instant

val MultiSignedWrpRequestTest by matrixSuite {

    val origin = "https://example.com"
    val dcqlRequest = CredentialPresentationRequestBuilder(
        RequestOptionsCredential(AtomicAttribute2023, SD_JWT),
    ).toDCQLRequest()

    suspend fun registrationCertificate(subject: String): String = SignJwt<WrpPayload>(
        EphemeralKeyWithSelfSignedCert(),
        JwsHeaderCertOrJwk(),
    )(
        type = "rc-wrp+jwt",
        payload = WrpPayload(
            subjectIdentifier = subject,
            country = "AT",
            registryUri = "https://registrar.example.invalid/wrp",
            srvDescription = emptyList(),
            entitlements = emptyList(),
            privacyPolicy = "https://relying-party.example.invalid/privacy",
            infoUri = "",
            certificatePolicy = "https://registrar.example.invalid/policy",
            iat = Instant.fromEpochSeconds(0),
            status = WrpStatus(WrpStatusList(0u, "https://registrar.example.invalid/status")),
        ),
        serializer = WrpPayload.serializer(),
    ).getOrThrow().toString()

    /** A multisigned request with one signer per entry of [registrationCertificates], `null` for none. */
    suspend fun multiSignedRequest(
        registrationCertificates: List<String?>,
    ): Pair<RequestParametersFrom.OpenId4VpDcApiMultiSigned, List<DcApiRequestSigner>> {
        val signers = registrationCertificates.map { wrprc ->
            val key = EphemeralKeyWithSelfSignedCert()
            DcApiRequestSigner(
                clientIdScheme = ClientIdScheme.CertificateHash(
                    chain = listOf(key.getCertificate()!!),
                    redirectUri = "$origin/callback",
                ),
                keyMaterial = key,
                verifierInfo = wrprc?.let { listOf(VerifierInfo(REGISTRATION_CERT_FORMAT, it)).toNonEmptyList() },
            )
        }
        val verifier = DcApiVerifier(
            keyMaterial = EphemeralKeyWithoutCert(),
            clientIdScheme = ClientIdScheme.PreRegistered(clientId = "verifier", redirectUri = "$origin/callback"),
            stateToAuthnRequestStore = DefaultMapStore(),
        )
        val jws = verifier.createAuthnRequest(
            OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf(origin),
            ),
            DcApiCreationOptions.OpenId4VpMultiSigned(signers),
        ).getOrThrow().digital.requests.single()
            .shouldBeInstanceOf<DigitalCredentialGetRequest.OpenId4VpMultiSigned>()
            .data.request.typed<AuthenticationRequestParameters, JwsGeneral>()
        return RequestParametersFrom.OpenId4VpDcApiMultiSigned(
            jwsTyped = jws,
            credentialIds = listOf("credential-1"),
            callingPackageName = "com.example.app",
            callingOrigin = origin,
        ) to signers
    }

    fun DcApiRequestSigner.signature(index: Int, status: VerifierSignature.Status, clientId: String = clientIdScheme.clientId) =
        VerifierSignature(
            signatureIndex = index,
            clientId = clientId,
            verifierInfo = verifierInfo?.toList(),
            status = status,
        )

    "only authenticated signers are validated, a copied header next to a forged signature is not" {
        val (request, signers) = multiSignedRequest(listOf(registrationCertificate("own"), registrationCertificate("victim")))

        val data = request.wrpRequestDataOfSigners(
            listOf(
                signers[0].signature(0, VerifierSignature.Status.AUTHENTICATED),
                signers[1].signature(1, VerifierSignature.Status.INVALID),
            )
        ).getOrThrow()

        data.map { it.signatureIndex } shouldBe listOf(0)
        data.single().clientId shouldBe signers[0].clientIdScheme.clientId
    }

    "each signer is validated with its own access and registration certificate" {
        val (request, signers) = multiSignedRequest(listOf(registrationCertificate("first"), null))

        val data = request.wrpRequestDataOfSigners(
            signers.mapIndexed { index, signer -> signer.signature(index, VerifierSignature.Status.AUTHENTICATED) }
        ).getOrThrow()

        data.map { it.requestData.getOrThrow().accessCertificate.certificateChain } shouldBe signers.map {
            listOf(it.keyMaterial.getCertificate()!!)
        }
        data[0].requestData.getOrThrow().registrationCertificate.keys.single()
            .shouldBeInstanceOf<WrpRegistrationCertificate.WrpJwtRegistrationCertificate>()
            .payload.subjectIdentifier shouldBe "first"
        data[1].requestData.getOrThrow().registrationCertificate shouldBe emptyMap()
    }

    "a signature result that does not match the protected header is invalid" {
        val (request, signers) = multiSignedRequest(listOf(null, null))

        val data = request.wrpRequestDataOfSigners(
            listOf(signers[0].signature(0, VerifierSignature.Status.AUTHENTICATED, signers[1].clientIdScheme.clientId))
        ).getOrThrow()

        data.single().requestData.exceptionOrNull().shouldNotBeNull().message shouldContain "does not match"
    }

    "requests with too many signatures are not validated" {
        val (request, signers) = multiSignedRequest(List(MAX_MULTISIGNED_WRP_SIGNERS + 1) { null })

        val result = request.wrpRequestDataOfSigners(
            signers.mapIndexed { index, signer -> signer.signature(index, VerifierSignature.Status.AUTHENTICATED) }
        )

        result.exceptionOrNull().shouldNotBeNull().message shouldContain "at most $MAX_MULTISIGNED_WRP_SIGNERS"
    }
}

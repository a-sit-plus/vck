package at.asitplus.wallet.lib.agent.relyingParty

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants.VerifierInfo.REGISTRATION_CERT_FORMAT
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.VerifierInfo
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpAuthenticationRequestValidator
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRegistrationCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrpCredentialRequest
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

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
}

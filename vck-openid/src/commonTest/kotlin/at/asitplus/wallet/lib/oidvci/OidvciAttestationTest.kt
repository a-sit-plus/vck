package at.asitplus.wallet.lib.oidvci

import at.asitplus.catching
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Clock.System

val OidvciAttestationTest by testSuite {
    withFixtureGenerator {
        object {
            val authorizationService = SimpleAuthorizationService(
                strategy = CredentialAuthorizationServiceStrategy(
                    setOf(ConstantIndex.AtomicAttribute2023, MobileDrivingLicenceScheme)
                ),
            )
            val oauth2Client = OAuth2Client()
            var issuer = CredentialIssuer(
                authorizationService = authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023, MobileDrivingLicenceScheme),
                proofValidator = ProofValidator(
                    verifyAttestationProof = { true },
                    requireKeyAttestation = true, // this is important, to require key attestation
                )
            )
            val state = uuid4().toString()
            lateinit var client: WalletService
            suspend fun getToken(scope: String): TokenResponseParameters {
                val authnRequest = oauth2Client.createAuthRequestJar(
                    state = state,
                    scope = scope,
                    resource = issuer.metadata.credentialIssuer
                )
                val input = authnRequest as RequestParameters
                val authnResponse = authorizationService.authorize(input) { catching { dummyUser() } }
                    .getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                val code = authnResponse.params?.code
                    .shouldNotBeNull()
                val tokenRequest = oauth2Client.createTokenRequestParameters(
                    state = state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = scope,
                    resource = issuer.metadata.credentialIssuer
                )
                return authorizationService.token(tokenRequest, null).getOrThrow()
            }

            fun buildClientWithKeyAttestation() =
                with(EphemeralKeyWithoutCert()) {
                    client = WalletService(
                        loadKeyAttestation = {
                            catching {
                                SignJwt<KeyAttestationJwt>(this, JwsHeaderCertOrJwk())(
                                    OpenIdConstants.KEY_ATTESTATION_JWT_TYPE,
                                    KeyAttestationJwt(
                                        issuedAt = System.now(),
                                        nonce = it.clientNonce,
                                        attestedKeys = setOf(this.jsonWebKey)
                                    ),
                                    KeyAttestationJwt.serializer(),
                                ).getOrThrow()
                            }
                        }
                    )
                }
        }
    } - {
        test("use key attestation for proof") {
            it.buildClientWithKeyAttestation()

            val requestOptions = WalletService.RequestOptions(
                ConstantIndex.AtomicAttribute2023,
                CredentialRepresentation.PLAIN_JWT
            )
            val credentialFormat =
                it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                    .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)
            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce
            it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = clientNonce
            ).getOrThrow().forEach { request ->
                request.shouldBeInstanceOf<WalletService.CredentialRequest.Plain>()
                val credential = it.issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = request,
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
                    .shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Plain>()
                    .response

                JwsSigned.deserialize(
                    VerifiableCredentialJws.serializer(),
                    credential.credentials.shouldNotBeEmpty()
                        .first().credentialString.shouldNotBeNull(),
                    vckJsonSerializer
                ).getOrThrow()
                    .payload.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
            }
        }

        test("use key attestation for proof, issuer does not verify it") {
            it.issuer = CredentialIssuer(
                authorizationService = it.authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023, MobileDrivingLicenceScheme),
                proofValidator = ProofValidator(
                    verifyAttestationProof = { false }, // do not accept key attestation
                    requireKeyAttestation = true, // this is important, to require key attestation
                )
            )
            it.buildClientWithKeyAttestation()

            val requestOptions = WalletService.RequestOptions(
                ConstantIndex.AtomicAttribute2023,
                CredentialRepresentation.PLAIN_JWT
            )
            val credentialFormat =
                it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                    .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)
            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce
            it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = clientNonce
            ).getOrThrow().forEach { request ->
                request.shouldBeInstanceOf<WalletService.CredentialRequest.Plain>()
                shouldThrow<OAuth2Exception> {
                    it.issuer.credential(
                        authorizationHeader = token.toHttpHeaderValue(),
                        params = request,
                        credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                    ).getOrThrow()
                }
            }
        }

        test("require key attestation for proof, but do not provide one") {
            it.client = WalletService(loadKeyAttestation = null)

            val requestOptions = WalletService.RequestOptions(
                ConstantIndex.AtomicAttribute2023,
                CredentialRepresentation.PLAIN_JWT
            )
            val credentialFormat =
                it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                    .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)
            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce

            shouldThrowAny {
                it.client.createCredential(
                    tokenResponse = token,
                    metadata = it.issuer.metadata,
                    credentialFormat = credentialFormat,
                    clientNonce = clientNonce
                ).getOrThrow()
            }
        }

    }
}

private fun dummyUser(): OidcUserInfoExtended = OidcUserInfoExtended.deserialize("{\"sub\": \"foo\"}").getOrThrow()

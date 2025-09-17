package at.asitplus.wallet.lib.oidvci

import at.asitplus.catching
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
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
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Clock.System

class OidvciAttestationTest : FunSpec({

    lateinit var authorizationService: SimpleAuthorizationService
    lateinit var issuer: CredentialIssuer
    lateinit var client: WalletService
    lateinit var state: String

    suspend fun getToken(scope: String): TokenResponseParameters {
        val authnRequest = client.oauth2Client.createAuthRequestJar(
            state = state,
            scope = scope,
            resource = issuer.metadata.credentialIssuer
        )
        val input = authnRequest as RequestParameters
        val authnResponse = authorizationService.authorize(input) { catching { dummyUser() } }
            .getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params.code
            .shouldNotBeNull()
        val tokenRequest = client.oauth2Client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.Code(code),
            scope = scope,
            resource = issuer.metadata.credentialIssuer
        )
        return authorizationService.token(tokenRequest, null).getOrThrow()
    }

    beforeEach {
        authorizationService = SimpleAuthorizationService(
            strategy = CredentialAuthorizationServiceStrategy(
                setOf(ConstantIndex.AtomicAttribute2023, MobileDrivingLicenceScheme)
            ),
        )
        issuer = CredentialIssuer(
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
        state = uuid4().toString()
    }

    test("use key attestation for proof") {
        client = buildClientWithKeyAttestation()

        val requestOptions = WalletService.RequestOptions(
            ConstantIndex.AtomicAttribute2023,
            CredentialRepresentation.PLAIN_JWT
        )
        val credentialFormat = client.selectSupportedCredentialFormat(requestOptions, issuer.metadata).shouldNotBeNull()
        val scope = credentialFormat.scope.shouldNotBeNull()
        val token = getToken(scope)
        val clientNonce = issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce
        client.createCredential(
            tokenResponse = token,
            metadata = issuer.metadata,
            credentialFormat = credentialFormat,
            clientNonce = clientNonce
        ).getOrThrow().forEach {
            it.shouldBeInstanceOf<WalletService.CredentialRequest.Plain>()
            val credential = issuer.credential(
                token.toHttpHeaderValue(),
                it.request,
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow()

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
        issuer = CredentialIssuer(
            authorizationService = authorizationService,
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
        client = buildClientWithKeyAttestation()

        val requestOptions = WalletService.RequestOptions(
            ConstantIndex.AtomicAttribute2023,
            CredentialRepresentation.PLAIN_JWT
        )
        val credentialFormat = client.selectSupportedCredentialFormat(requestOptions, issuer.metadata).shouldNotBeNull()
        val scope = credentialFormat.scope.shouldNotBeNull()
        val token = getToken(scope)
        val clientNonce = issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce
        client.createCredential(
            tokenResponse = token,
            metadata = issuer.metadata,
            credentialFormat = credentialFormat,
            clientNonce = clientNonce
        ).getOrThrow().forEach {
            it.shouldBeInstanceOf<WalletService.CredentialRequest.Plain>()
            shouldThrow<OAuth2Exception> {
                issuer.credential(
                    token.toHttpHeaderValue(),
                    it.request,
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
            }
        }
    }

    test("require key attestation for proof, but do not provide one") {
        client = WalletService(loadKeyAttestation = null)

        val requestOptions = WalletService.RequestOptions(
            ConstantIndex.AtomicAttribute2023,
            CredentialRepresentation.PLAIN_JWT
        )
        val credentialFormat = client.selectSupportedCredentialFormat(requestOptions, issuer.metadata).shouldNotBeNull()
        val scope = credentialFormat.scope.shouldNotBeNull()
        val token = getToken(scope)
        val clientNonce = issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce

        shouldThrowAny {
            client.createCredential(
                tokenResponse = token,
                metadata = issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = clientNonce
            ).getOrThrow()
        }
    }


})

private fun buildClientWithKeyAttestation(): WalletService {
    val keyMaterial = EphemeralKeyWithoutCert()
    val signKeyAttestation = SignJwt<KeyAttestationJwt>(keyMaterial, JwsHeaderCertOrJwk())
    return WalletService(
        loadKeyAttestation = {
            catching {
                signKeyAttestation(
                    OpenIdConstants.KEY_ATTESTATION_JWT_TYPE,
                    KeyAttestationJwt(
                        issuedAt = System.now(),
                        nonce = it.clientNonce,
                        attestedKeys = setOf(keyMaterial.jsonWebKey)
                    ),
                    KeyAttestationJwt.serializer(),
                ).getOrThrow()
            }
        }
    )
}

private fun dummyUser(): OidcUserInfoExtended = OidcUserInfoExtended.deserialize("{\"sub\": \"foo\"}").getOrThrow()

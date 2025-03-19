package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyOAuth2DataProvider
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.datetime.Clock.System

class OidvciAttestationTest : FunSpec({

    lateinit var authorizationService: SimpleAuthorizationService
    lateinit var issuer: CredentialIssuer
    lateinit var client: WalletService
    lateinit var state: String

    suspend fun getToken(scope: String): TokenResponseParameters {
        val authnRequest = client.oauth2Client.createAuthRequest(
            state = state,
            scope = scope,
            resource = issuer.metadata.credentialIssuer
        )
        val authnResponse = authorizationService.authorize(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        val code = authnResponse.params.code
            .shouldNotBeNull()
        val tokenRequest = client.oauth2Client.createTokenRequestParameters(
            state = state,
            authorization = OAuth2Client.AuthorizationForToken.Code(code),
            scope = scope,
            resource = issuer.metadata.credentialIssuer
        )
        return authorizationService.token(tokenRequest).getOrThrow()
    }

    beforeEach {
        authorizationService = SimpleAuthorizationService(
            strategy = CredentialAuthorizationServiceStrategy(
                DummyOAuth2DataProvider,
                setOf(ConstantIndex.AtomicAttribute2023, MobileDrivingLicenceScheme)
            ),
        )
        issuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = IssuerAgent(),
            credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023, MobileDrivingLicenceScheme),
            credentialProvider = DummyOAuth2IssuerCredentialDataProvider,
            verifyAttestationProof = { true },
            requireKeyAttestation = true, // this is important, to require key attestation
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
        val clientNonce = issuer.nonce().getOrThrow().clientNonce
        client.createCredentialRequest(token, issuer.metadata, credentialFormat, clientNonce).getOrThrow().forEach {
            val credential = issuer.credential(token.toHttpHeaderValue(), it).getOrThrow()
            val serializedCredential = credential.credentials.shouldNotBeEmpty()
                .first().credentialString.shouldNotBeNull()

            JwsSigned.Companion.deserialize<VerifiableCredentialJws>(
                VerifiableCredentialJws.Companion.serializer(),
                serializedCredential,
                vckJsonSerializer
            ).getOrThrow()
                .payload.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }

    test("use key attestation for proof, issuer does not verify it") {
        issuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = IssuerAgent(),
            credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023, MobileDrivingLicenceScheme),
            credentialProvider = DummyOAuth2IssuerCredentialDataProvider,
            verifyAttestationProof = { false }, // do not accept key attestation
            requireKeyAttestation = true, // this is important, to require key attestation
        )
        client = buildClientWithKeyAttestation()

        val requestOptions = WalletService.RequestOptions(
            ConstantIndex.AtomicAttribute2023,
            CredentialRepresentation.PLAIN_JWT
        )
        val credentialFormat = client.selectSupportedCredentialFormat(requestOptions, issuer.metadata).shouldNotBeNull()
        val scope = credentialFormat.scope.shouldNotBeNull()
        val token = getToken(scope)
        val clientNonce = issuer.nonce().getOrThrow().clientNonce
        client.createCredentialRequest(token, issuer.metadata, credentialFormat, clientNonce).getOrThrow().forEach {
            shouldThrow<OAuth2Exception> {
                issuer.credential(token.toHttpHeaderValue(), it).getOrThrow()
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
        val clientNonce = issuer.nonce().getOrThrow().clientNonce

        client.createCredentialRequest(token, issuer.metadata, credentialFormat, clientNonce).isFailure shouldBe true
    }


})

private fun buildClientWithKeyAttestation(): WalletService {
    val cryptoService = DefaultCryptoService(EphemeralKeyWithoutCert())
    val jwsService = DefaultJwsService(cryptoService)
    return WalletService(
        loadKeyAttestation = {
            runCatching {
                jwsService.createSignedJwsAddingParams(
                    header = JwsHeader(
                        algorithm = cryptoService.keyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
                        type = OpenIdConstants.KEY_ATTESTATION_JWT_TYPE
                    ),
                    payload = KeyAttestationJwt(
                        issuedAt = System.now(),
                        nonce = it.clientNonce,
                        attestedKeys = setOf(cryptoService.keyMaterial.jsonWebKey)
                    ),
                    serializer = KeyAttestationJwt.serializer(),
                    addKeyId = false,
                    addJsonWebKey = true,
                    addX5c = false,
                ).getOrThrow()
            }.wrap()
        }
    )
}
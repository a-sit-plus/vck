package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.EncryptJweFun
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyUserProvider
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf

class OidvciEncryptionTest : FunSpec({

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
        val authnResponse = authorizationService.authorize(authnRequest) { catching { DummyUserProvider.user } }
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
            strategy = CredentialAuthorizationServiceStrategy(setOf(ConstantIndex.AtomicAttribute2023)),
        )
        issuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = IssuerAgent(
                identifier = "https://issuer.example.com".toUri(),
                randomSource = RandomSource.Default
            ),
            credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023),
            encryptionService = IssuerEncryptionService(
                requireResponseEncryption = true, // this is important
                decryptionKeyMaterial = EphemeralKeyWithoutCert()
            ),
        )
        state = uuid4().toString()
        client = WalletService(
            encryptionService = WalletEncryptionService(
                requestEncryption = true, // this is important
                decryptionKeyMaterial = EphemeralKeyWithoutCert() // this is important
            )
        )
    }

    test("wallet encrypts credential request and decrypts credential response") {
        val requestOptions = WalletService.RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
        val credentialFormat = client.selectSupportedCredentialFormat(requestOptions, issuer.metadata).shouldNotBeNull()
        val scope = credentialFormat.scope.shouldNotBeNull()
        val token = getToken(scope)

        client.createCredential(
            tokenResponse = token,
            metadata = issuer.metadata,
            credentialFormat = credentialFormat,
            clientNonce = issuer.nonce().getOrThrow().clientNonce
        ).getOrThrow().forEach {
            it.shouldBeInstanceOf<WalletService.CredentialRequest.Encrypted>()
            issuer.credentialEncryptedRequest(
                authorizationHeader = token.toHttpHeaderValue(),
                input = it.request.serialize(),
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow().let { credential ->
                client.parseCredentialResponse(credential, PLAIN_JWT, ConstantIndex.AtomicAttribute2023)
                    .getOrThrow().first().shouldBeInstanceOf<Holder.StoreCredentialInput.Vc>().apply {
                        signedVcJws.payload.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
                    }
            }
        }
    }

    test("wallet does not encrypt credential request and decrypts credential response") {
        val requestOptions = WalletService.RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
        val credentialFormat = client.selectSupportedCredentialFormat(requestOptions, issuer.metadata).shouldNotBeNull()
        val scope = credentialFormat.scope.shouldNotBeNull()
        val token = getToken(scope)

        client.createCredential(
            tokenResponse = token,
            metadata = issuer.metadata,
            credentialFormat = credentialFormat,
            clientNonce = issuer.nonce().getOrThrow().clientNonce
        ).getOrThrow().forEach {
            issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = it,
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow().let { credential ->
                client.parseCredentialResponse(credential, PLAIN_JWT, ConstantIndex.AtomicAttribute2023)
                    .getOrThrow().first().shouldBeInstanceOf<Holder.StoreCredentialInput.Vc>().apply {
                        signedVcJws.payload.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
                    }
            }
        }
    }

    test("wallet does not encrypt credential request but issuer requires this") {
        issuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = IssuerAgent(
                identifier = "https://issuer.example.com".toUri(),
                randomSource = RandomSource.Default
            ),
            credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023),
            encryptionService = IssuerEncryptionService(
                requireResponseEncryption = true,
                decryptionKeyMaterial = EphemeralKeyWithoutCert(),
                requireRequestEncryption = true, // this is important for this test
            ),
        )

        val requestOptions = WalletService.RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
        val credentialFormat = client.selectSupportedCredentialFormat(requestOptions, issuer.metadata).shouldNotBeNull()
        val scope = credentialFormat.scope.shouldNotBeNull()
        val token = getToken(scope)

        client.createCredential(
            tokenResponse = token,
            metadata = issuer.metadata,
            credentialFormat = credentialFormat,
            clientNonce = issuer.nonce().getOrThrow().clientNonce
        ).getOrThrow().forEach {
            shouldThrow<OAuth2Exception.InvalidEncryptionParameters> {
                issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = it,
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
            }
        }
    }

    test("issuer fails to encrypt response") {
        issuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = IssuerAgent(
                identifier = "https://issuer.example.com".toUri(),
                randomSource = RandomSource.Default
            ),
            credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023),
            encryptionService = IssuerEncryptionService(
                requireResponseEncryption = true,
                encryptCredentialResponse = object : EncryptJweFun {
                    override suspend fun invoke(
                        header: JweHeader,
                        payload: String,
                        recipientKey: JsonWebKey,
                    ): KmmResult<JweEncrypted> = KmmResult.catching {
                        TODO("issuer fails to encrypt")
                    }
                }
            ),
        )
        val requestOptions = WalletService.RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
        val credentialFormat = client.selectSupportedCredentialFormat(requestOptions, issuer.metadata).shouldNotBeNull()
        val scope = credentialFormat.scope.shouldNotBeNull()
        val token = getToken(scope)

        client.createCredential(
            tokenResponse = token,
            metadata = issuer.metadata,
            credentialFormat = credentialFormat,
            clientNonce = issuer.nonce().getOrThrow().clientNonce
        ).getOrThrow().forEach {
            shouldThrowAny {
                issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = it,
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
            }
        }
    }


})

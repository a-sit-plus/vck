package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.DecryptJwe
import at.asitplus.wallet.lib.jws.DecryptJweFun
import at.asitplus.wallet.lib.jws.EncryptJweFun
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyOAuth2DataProvider
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf

class OidvciEncryptionTest : FunSpec({

    lateinit var authorizationService: SimpleAuthorizationService
    lateinit var issuer: CredentialIssuer
    lateinit var client: WalletService
    lateinit var state: String
    lateinit var decryptJwe: DecryptJweFun

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
            strategy = CredentialAuthorizationServiceStrategy(setOf(ConstantIndex.AtomicAttribute2023)),
            dataProvider = DummyOAuth2DataProvider,
        )
        issuer = CredentialIssuer(
            authorizationService = authorizationService,
            credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023),
            requireEncryption = true, // this is important, to require encryption
        )
        state = uuid4().toString()
        val decryptionKeyMaterial = EphemeralKeyWithoutCert()
        client = WalletService(
            requestEncryption = true, // this is important
            decryptionKeyMaterial = decryptionKeyMaterial // this is important
        )
        decryptJwe = DecryptJwe(decryptionKeyMaterial)
    }

    test("issuer fails to encrypt") {
        issuer = CredentialIssuer(
            authorizationService = authorizationService,
            credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023),
            requireEncryption = true, // this is important, to require encryption
            encryptCredentialRequest = object : EncryptJweFun {
                override suspend fun invoke(
                    header: JweHeader,
                    payload: String,
                    recipientKey: JsonWebKey,
                ): KmmResult<JweEncrypted> = KmmResult.catching {
                    TODO("issuer fails to encrypt")
                }
            }
        )
        val requestOptions = WalletService.RequestOptions(
            ConstantIndex.AtomicAttribute2023,
            ConstantIndex.CredentialRepresentation.PLAIN_JWT
        )
        val credentialFormat = client.selectSupportedCredentialFormat(requestOptions, issuer.metadata).shouldNotBeNull()
        val scope = credentialFormat.scope.shouldNotBeNull()
        val token = getToken(scope)
        val clientNonce = issuer.nonce().getOrThrow().clientNonce

        client.createCredentialRequest(token, issuer.metadata, credentialFormat, clientNonce).getOrThrow().forEach {
            shouldThrowAny {
                issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = it,
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                    issueCredential = { IssuerAgent().issueCredential(it) }
                ).getOrThrow()
            }
        }
    }

    test("decrypt received credential") {
        val requestOptions = WalletService.RequestOptions(
            ConstantIndex.AtomicAttribute2023,
            ConstantIndex.CredentialRepresentation.PLAIN_JWT
        )
        val credentialFormat =
            client.selectSupportedCredentialFormat(requestOptions, issuer.metadata).shouldNotBeNull()
        val scope = credentialFormat.scope.shouldNotBeNull()
        val token = getToken(scope)
        val clientNonce = issuer.nonce().getOrThrow().clientNonce

        client.createCredentialRequest(token, issuer.metadata, credentialFormat, clientNonce).getOrThrow().forEach {
            val credential = issuer.credential(
                token.toHttpHeaderValue(),
                it,
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                issueCredential = { IssuerAgent().issueCredential(it) }
            ).getOrThrow()
            val serializedCredential = credential.credentials.shouldNotBeEmpty()
                .first().credentialString.shouldNotBeNull()
            val jwe = JweEncrypted.Companion.deserialize(serializedCredential).getOrThrow()
            val plain = decryptJwe(jwe).getOrThrow().payload

            JwsSigned.Companion.deserialize<VerifiableCredentialJws>(
                VerifiableCredentialJws.Companion.serializer(),
                plain,
                vckJsonSerializer
            ).getOrThrow()
                .payload.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }

})
package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.LibraryInitializer
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialSubject
import at.asitplus.wallet.lib.oidvci.decodeFromPostBody
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass

class OidcSiopProtocolTest : FreeSpec({

    lateinit var relyingPartyUrl: String
    lateinit var walletUrl: String

    lateinit var holderCryptoService: CryptoService
    lateinit var verifierCryptoService: CryptoService

    lateinit var holder: Holder
    lateinit var verifier: Verifier

    lateinit var holderOidcSiopProtocol: OidcSiopWallet
    lateinit var verifierOidcSiopProtocol: OidcSiopVerifier

    beforeSpec {
        LibraryInitializer.registerExtensionLibrary(LibraryInitializer.ExtensionLibraryInfo(
            credentialScheme = TestCredentialScheme,
            serializersModule = kotlinx.serialization.modules.SerializersModule {
                polymorphic(CredentialSubject::class) {
                    subclass(TestCredential::class)
                }
            }
        ))
    }

    beforeEach {
        holderCryptoService = DefaultCryptoService()
        verifierCryptoService = DefaultCryptoService()
        holder = HolderAgent.newDefaultInstance(holderCryptoService)
        verifier = VerifierAgent.newDefaultInstance(verifierCryptoService.identifier)
        runBlocking {
            holder.storeCredentials(
                IssuerAgent.newDefaultInstance(
                    DefaultCryptoService(),
                    dataProvider = DummyCredentialDataProvider(),
                ).issueCredentialWithTypes(
                    holder.identifier,
                    listOf(ConstantIndex.AtomicAttribute2023.vcType)
                ).toStoreCredentialInput()
            )
        }

        holderOidcSiopProtocol = OidcSiopWallet.newInstance(
            holder = holder,
            cryptoService = holderCryptoService
        )
        verifierOidcSiopProtocol = OidcSiopVerifier.newInstance(
            verifier = verifier,
            cryptoService = verifierCryptoService
        )

        relyingPartyUrl = "https://example.com/${uuid4()}"
        walletUrl = "https://example.com/${uuid4()}"
    }

    "test with URLs" {
        val authnRequest = verifierOidcSiopProtocol.createAuthnRequestUrl(walletUrl, relyingPartyUrl)
        println(authnRequest)

        val authnResponse = holderOidcSiopProtocol.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()
        println(authnResponse)

        val result = verifierOidcSiopProtocol.validateAuthnResponse(authnResponse.url, relyingPartyUrl)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

    "test with POST" {
        val authnRequest = verifierOidcSiopProtocol.createAuthnRequestUrl(
            walletUrl,
            relyingPartyUrl,
            responseMode = OpenIdConstants.ResponseModes.POST
        )
        println(authnRequest)

        val authnResponse = holderOidcSiopProtocol.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Post>()
        println(authnResponse)
        authnResponse.url.shouldBe(relyingPartyUrl)

        val result = verifierOidcSiopProtocol.validateAuthnResponseFromPost(authnResponse.content, relyingPartyUrl)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

    "test with Query" {
        val authnRequest = verifierOidcSiopProtocol.createAuthnRequestUrl(
            walletUrl,
            relyingPartyUrl,
            responseMode = OpenIdConstants.ResponseModes.QUERY
        )
        println(authnRequest)
        authnRequest.shouldContain("?")
        authnRequest.shouldNotContain("#")

        val authnResponse = holderOidcSiopProtocol.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()
        println(authnResponse)
        authnResponse.url.shouldStartWith(relyingPartyUrl)

        val result = verifierOidcSiopProtocol.validateAuthnResponse(authnResponse.url, relyingPartyUrl)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

    "test with JAR" {
        val authnRequest = verifierOidcSiopProtocol.createAuthnRequestUrlWithRequestObject(walletUrl, relyingPartyUrl)
        println(authnRequest)

        val authnResponse = holderOidcSiopProtocol.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()
        val result = verifierOidcSiopProtocol.validateAuthnResponse(authnResponse.url, relyingPartyUrl)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

    "test with deserializing" {
        val authnRequest = verifierOidcSiopProtocol.createAuthnRequest(relyingPartyUrl)
        val authnRequestUrlParams = authnRequest.encodeToParameters().formUrlEncode()
        println(authnRequestUrlParams)

        val parsedAuthnRequest: AuthenticationRequestParameters = authnRequestUrlParams.decodeFromUrlQuery()
        val authnResponse = holderOidcSiopProtocol.createAuthnResponseParams(parsedAuthnRequest).getOrThrow()
        val authnResponseParams = authnResponse.encodeToParameters().formUrlEncode()
        println(authnResponseParams)

        val parsedAuthnResponse: AuthenticationResponseParameters = authnResponseParams.decodeFromPostBody()
        val result = verifierOidcSiopProtocol.validateAuthnResponse(parsedAuthnResponse, relyingPartyUrl)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

    "test specific credential" {
        holder.storeCredentials(
            IssuerAgent.newDefaultInstance(
                DefaultCryptoService(),
                dataProvider = TestCredentialDataProvider(),
            ).issueCredentialWithTypes(
                holder.identifier,
                listOf(TestCredentialScheme.vcType)
            ).toStoreCredentialInput()
        )

        val authnRequest = verifierOidcSiopProtocol.createAuthnRequestUrl(
            walletUrl,
            relyingPartyUrl,
            credentialScheme = TestCredentialScheme
        )
        println(authnRequest)

        val authnResponse = holderOidcSiopProtocol.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()
        println(authnResponse)

        val result = verifierOidcSiopProtocol.validateAuthnResponse(authnResponse.url, relyingPartyUrl)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<TestCredential>()
        }
    }
})
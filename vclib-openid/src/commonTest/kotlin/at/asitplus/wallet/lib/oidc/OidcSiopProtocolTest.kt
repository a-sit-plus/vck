package at.asitplus.wallet.lib.oidc

import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.oidvci.decodeFromPostBody
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking

class OidcSiopProtocolTest : FreeSpec({

    lateinit var relyingPartyUrl: String
    lateinit var walletUrl: String

    lateinit var holderCryptoService: CryptoService
    lateinit var verifierCryptoService: CryptoService

    lateinit var holderAgent: Holder
    lateinit var verifierAgent: Verifier

    lateinit var holderSiop: OidcSiopWallet
    lateinit var verifierSiop: OidcSiopVerifier

    beforeEach {
        holderCryptoService = DefaultCryptoService()
        verifierCryptoService = DefaultCryptoService()
        relyingPartyUrl = "https://example.com/rp/${uuid4()}"
        walletUrl = "https://example.com/wallet/${uuid4()}"
        holderAgent = HolderAgent.newDefaultInstance(holderCryptoService)
        verifierAgent = VerifierAgent.newDefaultInstance(verifierCryptoService.publicKey.didEncoded)
        runBlocking {
            holderAgent.storeCredentials(
                IssuerAgent.newDefaultInstance(
                    DefaultCryptoService(),
                    dataProvider = DummyCredentialDataProvider(),
                ).issueCredential(
                    subjectPublicKey = holderCryptoService.publicKey,
                    attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                    representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).toStoreCredentialInput()
            )
        }

        holderSiop = OidcSiopWallet.newInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService
        )
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            cryptoService = verifierCryptoService,
            relyingPartyUrl = relyingPartyUrl,
        )
    }

    "test with Fragment" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            credentialRepresentation = ConstantIndex.CredentialRepresentation.PLAIN_JWT
        ).also { println(it) }

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>().also { println(it) }

        authnResponse.url.shouldNotContain("?")
        authnResponse.url.shouldContain("#")
        authnResponse.url.shouldStartWith(relyingPartyUrl)

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()

        verifierSiop.validateAuthnResponse(
            (holderSiop.createAuthnResponse(
                verifierSiop.createAuthnRequestUrl(
                    walletUrl = walletUrl,
                    credentialRepresentation = ConstantIndex.CredentialRepresentation.PLAIN_JWT
                )
            )
                .getOrThrow() as OidcSiopWallet.AuthenticationResponseResult.Redirect).url
        ).shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
    }

    "test with QR Code" {
        val metadataUrlNonce = uuid4().toString()
        val metadataUrl = "https://example.com/$metadataUrlNonce"
        val requestUrlNonce = uuid4().toString()
        val requestUrl = "https://example.com/$requestUrlNonce"
        val qrcode = verifierSiop.createQrCodeUrl(walletUrl, metadataUrl, requestUrl)
        qrcode shouldContain metadataUrlNonce
        qrcode shouldContain requestUrlNonce

        val metadataObject = verifierSiop.createSignedMetadata(ConstantIndex.CredentialRepresentation.PLAIN_JWT).getOrThrow()
            .also { println(it) }
        DefaultVerifierJwsService().verifyJwsObject(metadataObject).shouldBeTrue()

        val authnRequest = verifierSiop.createAuthnRequestAsRequestObject(credentialRepresentation = ConstantIndex.CredentialRepresentation.PLAIN_JWT).getOrThrow()
        authnRequest.clientId shouldBe relyingPartyUrl
        val jar = authnRequest.request
        jar.shouldNotBeNull()
        DefaultVerifierJwsService().verifyJwsObject(JwsSigned.parse(jar)!!).shouldBeTrue()

        val authnResponse = holderSiop.createAuthnResponse(jar).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
    }

    "test with POST" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            credentialRepresentation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
            responseMode = OpenIdConstants.ResponseModes.POST
        ).also { println(it) }

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Post>().also { println(it) }
        authnResponse.url.shouldBe(relyingPartyUrl)

        val result = verifierSiop.validateAuthnResponseFromPost(authnResponse.content)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

    "test with Query" {
        val expectedState = uuid4().toString()
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            credentialRepresentation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
            responseMode = OpenIdConstants.ResponseModes.QUERY,
            state = expectedState
        ).also { println(it) }

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>().also { println(it) }

        authnResponse.url.shouldContain("?")
        authnResponse.url.shouldNotContain("#")
        authnResponse.url.shouldStartWith(relyingPartyUrl)

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.state.shouldBe(expectedState)
    }

    "test with deserializing" {
        val authnRequest =
            verifierSiop.createAuthnRequest(credentialRepresentation = ConstantIndex.CredentialRepresentation.PLAIN_JWT)
        val authnRequestUrlParams = authnRequest.encodeToParameters().formUrlEncode().also { println(it) }

        val parsedAuthnRequest: AuthenticationRequestParameters = authnRequestUrlParams.decodeFromUrlQuery()
        val authnResponse = holderSiop.createAuthnResponseParams(parsedAuthnRequest).getOrThrow()
        val authnResponseParams = authnResponse.encodeToParameters().formUrlEncode().also { println(it) }

        val parsedAuthnResponse: AuthenticationResponseParameters = authnResponseParams.decodeFromPostBody()
        val result = verifierSiop.validateAuthnResponse(parsedAuthnResponse)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

    "test specific credential" {
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            cryptoService = verifierCryptoService,
            relyingPartyUrl = relyingPartyUrl,
            credentialScheme = ConstantIndex.AtomicAttribute2023,
        )

        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            credentialRepresentation = ConstantIndex.CredentialRepresentation.PLAIN_JWT
        ).also { println(it) }

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>().also { println(it) }

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }
})
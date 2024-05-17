package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier.RequestOptions
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking

class OidcSiopX509SanDnsTest : FreeSpec({

    lateinit var responseUrl: String
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
        responseUrl = "https://example.com"
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
                    representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                ).toStoreCredentialInput()
            )
        }

        holderSiop = OidcSiopWallet.newDefaultInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService
        )
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            cryptoService = verifierCryptoService,
            relyingPartyUrl = null,
            responseUrl = responseUrl,
            x5c = listOf(verifierCryptoService.certificate!!)
        )
    }

    "test with Fragment" {
        val authnRequest = verifierSiop.createAuthnRequestAsSignedRequestObject(
            requestOptions = RequestOptions(
                representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                responseMode = OpenIdConstants.ResponseMode.DIRECT_POST_JWT,
                requestedAttributes = listOf("given-name")
            )
        ).also { println(it) }.getOrThrow()

        val authnResponse = holderSiop.startAuthenticationResponsePreparation(authnRequest.serialize()).getOrThrow().let {
            holderSiop.finalizeAuthenticationResponseResult(it)
        }.getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Post>().also { println(it) }

        val result = verifierSiop.validateAuthnResponseFromPost(authnResponse.params.formUrlEncode())
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessSdJwt>()
        result.disclosures.shouldNotBeEmpty()

    }
})


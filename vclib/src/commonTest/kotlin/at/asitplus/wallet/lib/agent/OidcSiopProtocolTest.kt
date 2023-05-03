package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.SchemaIndex
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking

class OidcSiopProtocolTest : FreeSpec({

    lateinit var holderCryptoService: CryptoService
    lateinit var verifierCryptoService: CryptoService

    lateinit var holder: Holder
    lateinit var verifier: Verifier

    lateinit var holderOidcSiopProtocol: OidcSiopProtocol
    lateinit var verifierOidcSiopProtocol: OidcSiopProtocol

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
                    listOf(ConstantIndex.Generic.vcType)
                ).toStoreCredentialInput()
            )
        }

        holderOidcSiopProtocol = OidcSiopProtocol.newHolderInstance(
            holder = holder,
            cryptoService = holderCryptoService
        )
        verifierOidcSiopProtocol = OidcSiopProtocol.newVerifierInstance(
            verifier = verifier,
            cryptoService = verifierCryptoService
        )
    }

    // TODO also test with "response_mode=post" = cross-device SIOP

    "test" {
        val authnRequest = verifierOidcSiopProtocol.createAuthnRequest()
        println(authnRequest) // len: 1084 chars

        val authnResponse = holderOidcSiopProtocol.createAuthnResponse(authnRequest)!!
        println(authnResponse) // len: 3702 chars with one "atomic" credential (string-string)

        val result = verifierOidcSiopProtocol.validateAuthnResponse(authnResponse)
        println(result)
        result.shouldBeInstanceOf<OidcSiopProtocol.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

})

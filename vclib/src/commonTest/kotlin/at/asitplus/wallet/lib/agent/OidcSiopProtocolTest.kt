package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.SchemaIndex
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.parseUrlEncodedParameters
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
        verifier = VerifierAgent.newDefaultInstance(verifierCryptoService.keyId)
        runBlocking {
            holder.storeCredentials(
                IssuerAgent.newDefaultInstance(
                    DefaultCryptoService(),
                    dataProvider = DummyCredentialDataProvider(),
                ).issueCredentials(
                    holderCryptoService.keyId,
                    listOf("${SchemaIndex.ATTR_GENERIC_PREFIX}/given-name")
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
        authnRequest.shouldContain("redirect_uri=https%3A%2F%2Fwallet.a-sit.at%2Fverifier")
        authnRequest.shouldNotContain("redirect_uri=%22https%3A%2F%2Fwallet.a-sit.at%2Fverifier%22")

        val authnResponse = holderOidcSiopProtocol.createAuthnResponse(authnRequest)
        authnResponse.shouldNotBeNull()
        println(authnResponse) // len: 3702 chars with one "atomic" credential (string-string)
        authnResponse.shouldContain("id_token=")
        authnResponse.shouldNotContain("id_token=%22")

        val result = verifierOidcSiopProtocol.validateAuthnResponse(authnResponse)
        println(result)
        result.shouldBeInstanceOf<OidcSiopProtocol.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

})

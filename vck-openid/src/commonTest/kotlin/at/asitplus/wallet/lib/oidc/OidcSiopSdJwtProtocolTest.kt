package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyWithCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier.RequestOptions
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSingleElement
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf

class OidcSiopSdJwtProtocolTest : FreeSpec({

    lateinit var relyingPartyUrl: String
    lateinit var walletUrl: String

    lateinit var holderKeyPair: KeyWithCert
    lateinit var verifierKeyPair: KeyWithCert

    lateinit var holderAgent: Holder
    lateinit var verifierAgent: Verifier

    lateinit var holderSiop: OidcSiopWallet
    lateinit var verifierSiop: OidcSiopVerifier

    beforeEach {
        holderKeyPair = EphemeralKeyWithSelfSignedCert()
        verifierKeyPair = EphemeralKeyWithSelfSignedCert()
        relyingPartyUrl = "https://example.com/rp/${uuid4()}"
        walletUrl = "https://example.com/wallet/${uuid4()}"
        holderAgent = HolderAgent(holderKeyPair)
        verifierAgent = VerifierAgent(verifierKeyPair)

        holderAgent.storeCredential(
            IssuerAgent(
                EphemeralKeyWithSelfSignedCert(),
                DummyCredentialDataProvider(),
            ).issueCredential(
                holderKeyPair.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.SD_JWT,
            ).getOrThrow().toStoreCredentialInput()
        )

        holderSiop = OidcSiopWallet(
            holder = holderAgent,
        )
        verifierSiop = OidcSiopVerifier(
            keyPairAdapter = verifierKeyPair,
            relyingPartyUrl = relyingPartyUrl,
        )
    }

    "test with Fragment" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(
                representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                credentialScheme = ConstantIndex.AtomicAttribute2023,
                requestedAttributes = listOf("given_name")
            ),
        ).also { println(it) }

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>().also { println(it) }

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessSdJwt>()
        result.disclosures.shouldNotBeEmpty()

        assertSecondRun(verifierSiop, holderSiop, walletUrl)
    }

    "Selective Disclosure with custom credential" {
        val requestedClaim = "given_name"
        verifierSiop = OidcSiopVerifier(
            keyPairAdapter = verifierKeyPair,
            relyingPartyUrl = relyingPartyUrl,
        )
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(
                representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                credentialScheme = ConstantIndex.AtomicAttribute2023,
                requestedAttributes = listOf(requestedClaim)
            )
        ).also { println(it) }
        authnRequest shouldContain requestedClaim

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>().also { println(it) }

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessSdJwt>()
        val sdJwt = result.sdJwt.also { println(it) }

        result.disclosures.shouldNotBeEmpty()
        result.disclosures.shouldBeSingleton()
        result.disclosures.shouldHaveSingleElement { it.claimName == requestedClaim }
        sdJwt.shouldNotBeNull()
    }

})

private suspend fun assertSecondRun(
    verifierSiop: OidcSiopVerifier,
    holderSiop: OidcSiopWallet,
    walletUrl: String
) {
    val authnRequestUrl = verifierSiop.createAuthnRequestUrl(
        walletUrl = walletUrl,
        requestOptions = RequestOptions(representation = ConstantIndex.CredentialRepresentation.SD_JWT)
    )
    val authnResponse = holderSiop.createAuthnResponse(authnRequestUrl)
    val url = (authnResponse.getOrThrow() as AuthenticationResponseResult.Redirect).url
    val validation = verifierSiop.validateAuthnResponse(url)
    validation.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessSdJwt>()
}
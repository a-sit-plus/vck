package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
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

    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial

    lateinit var holderAgent: Holder
    lateinit var verifierAgent: Verifier

    lateinit var holderSiop: OidcSiopWallet
    lateinit var verifierSiop: OidcSiopVerifier

    beforeEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithoutCert()
        relyingPartyUrl = "https://example.com/rp/${uuid4()}"
        walletUrl = "https://example.com/wallet/${uuid4()}"
        holderAgent = HolderAgent(holderKeyMaterial)
        verifierAgent = VerifierAgent(verifierKeyMaterial)

        holderAgent.storeCredential(
            IssuerAgent().issueCredential(
                DummyCredentialDataProvider().getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.SD_JWT,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )

        holderSiop = OidcSiopWallet(
            holder = holderAgent,
        )
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyMaterial,
            relyingPartyUrl = relyingPartyUrl,
        )
    }

    "Selective Disclosure with custom credential" {
        val requestedClaim = CLAIM_GIVEN_NAME
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyMaterial,
            relyingPartyUrl = relyingPartyUrl,
        )
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(
                credentials = setOf(
                    OidcSiopVerifier.RequestOptionsCredential(
                        ConstantIndex.AtomicAttribute2023,
                        ConstantIndex.CredentialRepresentation.SD_JWT,
                        listOf(requestedClaim)
                    )
                )
            )
        )
        authnRequest shouldContain requestedClaim

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessSdJwt>()
        result.sdJwt.shouldNotBeNull()
        result.disclosures.shouldNotBeEmpty()
        result.disclosures.shouldBeSingleton()
        result.disclosures.shouldHaveSingleElement { it.claimName == requestedClaim }
    }

})

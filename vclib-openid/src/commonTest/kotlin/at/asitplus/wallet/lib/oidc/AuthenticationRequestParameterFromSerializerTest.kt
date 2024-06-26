package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.RandomKeyPairAdapter
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*

class AuthenticationRequestParameterFromSerializerTest : FreeSpec({

    val relyingPartyUrl = "https://example.com/rp/${uuid4()}"
    val walletUrl = "https://example.com/wallet/${uuid4()}"
    val responseUrl = "https://example.com/rp/${uuid4()}"

    val holderKeyPair = RandomKeyPairAdapter()
    val oidcSiopWallet = OidcSiopWallet.newDefaultInstance(
        keyPairAdapter = holderKeyPair,
        holder = HolderAgent(holderKeyPair),
    )

    val verifierSiop = OidcSiopVerifier.newInstance(
        verifier = VerifierAgent(RandomKeyPairAdapter()),
        relyingPartyUrl = relyingPartyUrl,
        responseUrl = responseUrl,
    )

    val representations = listOf(
        ConstantIndex.CredentialRepresentation.PLAIN_JWT,
        ConstantIndex.CredentialRepresentation.SD_JWT,
        ConstantIndex.CredentialRepresentation.ISO_MDOC
    )

    representations.forEach { representation ->
        val reqOptions = OidcSiopVerifier.RequestOptions(
            credentialScheme = ConstantIndex.AtomicAttribute2023,
            representation = representation,
        )

        "URL test $representation" {
            val authnRequest = verifierSiop.createAuthnRequestUrl(
                walletUrl = walletUrl,
                requestOptions = reqOptions
            )
            val basis = oidcSiopWallet.parseAuthenticationRequestParameters(authnRequest).getOrThrow()
            basis.shouldBeInstanceOf<AuthenticationRequestParametersFrom.Uri>()
            AuthenticationRequestParametersFrom.deserialize(basis.serialize()).getOrThrow() shouldBe basis
        }

        "Json test $representation" {
            val authnRequest = verifierSiop.createAuthnRequest(requestOptions = reqOptions).serialize()
            val basis = oidcSiopWallet.parseAuthenticationRequestParameters(authnRequest).getOrThrow()
            basis.shouldBeInstanceOf<AuthenticationRequestParametersFrom.Json>()
            AuthenticationRequestParametersFrom.deserialize(basis.serialize()).getOrThrow() shouldBe basis
        }

        "JwsSigned test $representation" {
            val authnRequestUrl =
                verifierSiop.createAuthnRequestUrlWithRequestObject(
                    walletUrl = walletUrl,
                    requestOptions = reqOptions
                ).getOrThrow()
            val authnRequest123: AuthenticationRequestParameters =
                Url(authnRequestUrl).encodedQuery.decodeFromUrlQuery()
            authnRequest123.clientId shouldBe relyingPartyUrl
            val authnRequest10 = authnRequest123.request ?: throw Exception("Authn request is null")
            val basis = oidcSiopWallet.parseAuthenticationRequestParameters(authnRequest10).getOrThrow()
            basis.shouldBeInstanceOf<AuthenticationRequestParametersFrom.JwsSigned>()
            AuthenticationRequestParametersFrom.deserialize(basis.serialize()).getOrThrow() shouldBe basis
        }
    }
})
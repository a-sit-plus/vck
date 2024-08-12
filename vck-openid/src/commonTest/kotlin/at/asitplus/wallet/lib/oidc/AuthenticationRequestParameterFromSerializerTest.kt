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
import kotlinx.serialization.encodeToString

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
        val reqOptions = RequestOptions(
            credentialScheme = ConstantIndex.AtomicAttribute2023,
            representation = representation,
        )

        "URL test $representation" {
            val authnRequest = verifierSiop.createAuthnRequestUrl(
                walletUrl = walletUrl,
                requestOptions = reqOptions
            )
            val params = oidcSiopWallet.parseAuthenticationRequestParameters(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationRequestParametersFrom.Uri>()

            val serialized = params.serialize()

            AuthenticationRequestParametersFrom.deserialize(serialized).getOrThrow() shouldBe params
        }

        "Json test $representation" {
            val authnRequest = verifierSiop.createAuthnRequest(requestOptions = reqOptions).serialize()
            val params = oidcSiopWallet.parseAuthenticationRequestParameters(authnRequest).getOrThrow()

            val serialized = params.serialize()

            AuthenticationRequestParametersFrom.deserialize(serialized).getOrThrow() shouldBe params
        }

        "JwsSigned test $representation" {
            val authnRequestUrl = verifierSiop.createAuthnRequestUrlWithRequestObject(
                walletUrl = walletUrl,
                requestOptions = reqOptions
            ).getOrThrow()
            val interim1: AuthenticationRequestParameters =
                Url(authnRequestUrl).encodedQuery.decodeFromUrlQuery()
            interim1.clientId shouldBe relyingPartyUrl

            val interim2 = interim1.request ?: throw Exception("Authn request is null")
            val params = oidcSiopWallet.parseAuthenticationRequestParameters(interim2).getOrThrow()

            val serialized = params.serialize()

            AuthenticationRequestParametersFrom.deserialize(serialized).getOrThrow() shouldBe params
        }
    }
})
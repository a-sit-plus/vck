package at.asitplus.wallet.lib.oidc

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlinx.serialization.encodeToString

class AuthenticationRequestParameterFromSerializerTest : FreeSpec({

    val clientId = "https://example.com/rp/${uuid4()}"
    val walletUrl = "https://example.com/wallet/${uuid4()}"

    val holderKeyMaterial = EphemeralKeyWithoutCert()
    val oidcSiopWallet = OidcSiopWallet(
        keyMaterial = holderKeyMaterial,
        holder = HolderAgent(holderKeyMaterial),
    )

    val verifierSiop = OidcSiopVerifier(
        clientIdScheme = OidcSiopVerifier.ClientIdScheme.RedirectUri(clientId),
    )

    val representations = listOf(
        ConstantIndex.CredentialRepresentation.PLAIN_JWT,
        ConstantIndex.CredentialRepresentation.SD_JWT,
        ConstantIndex.CredentialRepresentation.ISO_MDOC
    )


    representations.forEach { representation ->
        val reqOptions = OidcSiopVerifier.RequestOptions(
            credentials = setOf(
                OidcSiopVerifier.RequestOptionsCredential(
                    ConstantIndex.AtomicAttribute2023, representation
                )
            )
        )

        "URL test $representation" {
            val authnRequest = verifierSiop.createAuthnRequestUrl(
                walletUrl = walletUrl,
                requestOptions = reqOptions
            )
            val params = oidcSiopWallet.parseAuthenticationRequestParameters(authnRequest).getOrThrow()
                .shouldBeInstanceOf<RequestParametersFrom.Uri<AuthenticationRequestParameters>>()

            val serialized = vckJsonSerializer.encodeToString(params)
            val deserialized = vckJsonSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(serialized)
            deserialized shouldBe params
        }

        "Json test $representation" {
            val authnRequest = verifierSiop.createAuthnRequest(requestOptions = reqOptions).serialize()
            val params = oidcSiopWallet.parseAuthenticationRequestParameters(authnRequest).getOrThrow()

            val serialized = vckJsonSerializer.encodeToString(params)
            val deserialized = vckJsonSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(serialized)
            deserialized shouldBe params
        }

        "JwsSigned test $representation" {
            val authnRequestUrl = verifierSiop.createAuthnRequestUrlWithRequestObject(
                walletUrl = walletUrl,
                requestOptions = reqOptions
            ).getOrThrow()
            val interim1: AuthenticationRequestParameters =
                Url(authnRequestUrl).encodedQuery.decodeFromUrlQuery()
            interim1.clientId shouldBe clientId

            val interim2 = interim1.request ?: throw Exception("Authn request is null")
            val params = oidcSiopWallet.parseAuthenticationRequestParameters(interim2).getOrThrow()

            val serialized = vckJsonSerializer.encodeToString(params)
            val deserialized = vckJsonSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(serialized)
            deserialized shouldBe params
        }
    }
})
package at.asitplus.wallet.lib.openid

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
    val holderOid4vp = OpenId4VpHolder(
        keyMaterial = holderKeyMaterial,
        holder = HolderAgent(holderKeyMaterial),
    )
    val verifierOid4vp = OpenId4VpVerifier(
        clientIdScheme = ClientIdScheme.RedirectUri(clientId),
    )
    val representations = listOf(
        ConstantIndex.CredentialRepresentation.PLAIN_JWT,
        ConstantIndex.CredentialRepresentation.SD_JWT,
        ConstantIndex.CredentialRepresentation.ISO_MDOC
    )

    representations.forEach { representation ->
        val reqOptions = RequestOptions(
            credentials = setOf(
                RequestOptionsCredential(
                    ConstantIndex.AtomicAttribute2023, representation
                )
            )
        )

        "URL test $representation" {
            val authnRequest = verifierOid4vp.createAuthnRequest(
                reqOptions,
                OpenId4VpVerifier.CreationOptions.Query(walletUrl)
            ).getOrThrow().url

            val params = holderOid4vp.parseAuthenticationRequestParameters(authnRequest).getOrThrow()
                .shouldBeInstanceOf<RequestParametersFrom.Uri<AuthenticationRequestParameters>>()

            val serialized = vckJsonSerializer.encodeToString(params)
            val deserialized = vckJsonSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(serialized)
            deserialized shouldBe params
        }

        "Json test $representation" {
            val authnRequest = verifierOid4vp.createAuthnRequest(requestOptions = reqOptions).serialize()
            val params = holderOid4vp.parseAuthenticationRequestParameters(authnRequest).getOrThrow()

            val serialized = vckJsonSerializer.encodeToString(params)
            val deserialized = vckJsonSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(serialized)
            deserialized shouldBe params
        }

        "JwsSigned test $representation" {
            val authnRequestUrl = verifierOid4vp.createAuthnRequest(
                reqOptions, OpenId4VpVerifier.CreationOptions.SignedRequestByValue(walletUrl)
            ).getOrThrow().url
            val interim1: AuthenticationRequestParameters =
                Url(authnRequestUrl).encodedQuery.decodeFromUrlQuery()
            interim1.clientId shouldBe clientId

            val interim2 = interim1.request ?: throw Exception("Authn request is null")
            val params = holderOid4vp.parseAuthenticationRequestParameters(interim2).getOrThrow()

            val serialized = vckJsonSerializer.encodeToString(params)
            val deserialized = vckJsonSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(serialized)
            deserialized shouldBe params
        }
    }
})
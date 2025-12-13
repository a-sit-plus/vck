package at.asitplus.wallet.lib.openid

import at.asitplus.dcapi.request.DCAPIWalletRequest
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*

val AuthenticationRequestParameterFromSerializerTest by testSuite {

    val clientId = "PRE-REGISTERED-CLIENT"
    val redirectUrl = "https://example.com/rp/${uuid4()}"
    val walletUrl = "https://example.com/wallet/${uuid4()}"
    val holderKeyMaterial = EphemeralKeyWithoutCert()
    val holderOid4vp = OpenId4VpHolder(
        keyMaterial = holderKeyMaterial,
        holder = HolderAgent(holderKeyMaterial),
        randomSource = RandomSource.Default,
    )
    val verifierOid4vp = OpenId4VpVerifier(
        clientIdScheme = ClientIdScheme.PreRegistered(clientId, redirectUrl),
    )
    val representations = listOf(
        ConstantIndex.CredentialRepresentation.PLAIN_JWT,
        ConstantIndex.CredentialRepresentation.SD_JWT,
        ConstantIndex.CredentialRepresentation.ISO_MDOC
    )

    representations.forEach { representation ->
        val reqOptions = OpenId4VpRequestOptions(
            credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, representation))
        )

        "URL test $representation" {
            val authnRequest = verifierOid4vp.createAuthnRequest(
                reqOptions,
                OpenId4VpVerifier.CreationOptions.Query(walletUrl)
            ).getOrThrow().url

            val params = holderOid4vp.startAuthorizationResponsePreparation(authnRequest).getOrThrow().request
                .shouldBeInstanceOf<RequestParametersFrom.Uri<AuthenticationRequestParameters>>()

            val serialized = vckJsonSerializer.encodeToString(params)
            vckJsonSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(serialized)
                .shouldBe(params)
        }

        "Json test $representation" {
            val authnRequest = vckJsonSerializer.encodeToString(
                verifierOid4vp.createAuthnRequest(requestOptions = reqOptions)
            )
            authnRequest.shouldNotContain(DifInputDescriptor::class.simpleName!!)
            val params = holderOid4vp.startAuthorizationResponsePreparation(authnRequest).getOrThrow().request
                .shouldBeInstanceOf<RequestParametersFrom.Json<AuthenticationRequestParameters>>()

            val serialized = vckJsonSerializer.encodeToString(params)
            vckJsonSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(serialized)
                .shouldBe(params)
        }

        "DcApiUnsigned test $representation" {
            val authnRequest = DCAPIWalletRequest.OpenId4VpUnsigned(
                request = verifierOid4vp.createAuthnRequest(requestOptions = reqOptions),
                credentialId = "1",
                callingPackageName = "com.example.app",
                callingOrigin = "https://example.com"
            )

            val params = holderOid4vp.startAuthorizationResponsePreparation(authnRequest).getOrThrow().request
                .shouldBeInstanceOf<RequestParametersFrom.DcApiUnsigned<AuthenticationRequestParameters>>()

            val serialized = vckJsonSerializer.encodeToString(params)
            vckJsonSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(serialized)
                .shouldBe(params)
        }

        "JwsSigned test $representation" {
            val authnRequestUrl = verifierOid4vp.createAuthnRequest(
                reqOptions, OpenId4VpVerifier.CreationOptions.SignedRequestByValue(walletUrl)
            ).getOrThrow().url

            val jarRequest: JarRequestParameters = Url(authnRequestUrl).encodedQuery.decodeFromUrlQuery()
            jarRequest.clientId shouldBe clientId
            val serializedRequest = jarRequest.request.shouldNotBeNull()
            val params = holderOid4vp.startAuthorizationResponsePreparation(serializedRequest).getOrThrow().request
                .shouldBeInstanceOf<RequestParametersFrom.JwsSigned<AuthenticationRequestParameters>>()

            val serialized = vckJsonSerializer.encodeToString(params)
            vckJsonSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(serialized)
                .shouldBe(params)
        }

        "DcApiSigned test $representation" {
            val authnRequestUrl = verifierOid4vp.createAuthnRequest(
                reqOptions, OpenId4VpVerifier.CreationOptions.SignedRequestByValue(walletUrl)
            ).getOrThrow().url

            val jarRequest: JarRequestParameters = Url(authnRequestUrl).encodedQuery.decodeFromUrlQuery()
            jarRequest.clientId shouldBe clientId
            val serializedRequest = jarRequest.request.shouldNotBeNull()
            val authnRequest = DCAPIWalletRequest.OpenId4VpSigned(
                request = jarRequest,
                credentialId = "1",
                callingPackageName = "com.example.app",
                callingOrigin = "https://example.com"
            )

            val params = holderOid4vp.startAuthorizationResponsePreparation(authnRequest).getOrThrow().request
                .shouldBeInstanceOf<RequestParametersFrom.DcApiSigned<AuthenticationRequestParameters>>()

            val serialized = vckJsonSerializer.encodeToString(params)
            vckJsonSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(serialized)
                .shouldBe(params)
        }
    }
}
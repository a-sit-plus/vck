package at.asitplus.wallet.lib.openid

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.JwsTyped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.toJwsFlattened
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import com.benasher44.uuid.uuid4
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*

val AuthenticationRequestParameterFromSerializerTest by matrixSuite {

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
    val representations = listOf(PLAIN_JWT, SD_JWT, ISO_MDOC)

    representations.forEach { representation ->
        val reqOptions = OpenId4VpRequestOptions(
            presentationRequest = CredentialPresentationRequestBuilder(
                RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, representation)
            ).toDCQLRequest()
        )

        "URL test $representation" {
            val authnRequest = verifierOid4vp.createAuthnRequest(
                reqOptions,
                CreationOptions.Query(walletUrl)
            ).getOrThrow().url

            val params = holderOid4vp.startAuthorizationResponsePreparation(authnRequest).getOrThrow().request
                .shouldBeInstanceOf<RequestParametersFrom.Uri<AuthenticationRequestParameters>>()

            val serialized =
                joseCompliantSerializer.encodeToString<RequestParametersFrom<AuthenticationRequestParameters>>(params)
            joseCompliantSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(serialized)
                .shouldBe(params)
        }

        "Json test $representation" {
            val authnRequest = joseCompliantSerializer.encodeToString(
                verifierOid4vp.createPlainAuthnRequest(reqOptions)
            )
            authnRequest.shouldNotContain(DifInputDescriptor::class.simpleName!!)
            val params = holderOid4vp.startAuthorizationResponsePreparation(authnRequest).getOrThrow().request
                .shouldBeInstanceOf<RequestParametersFrom.Json<AuthenticationRequestParameters>>()

            val serialized =
                joseCompliantSerializer.encodeToString<RequestParametersFrom<AuthenticationRequestParameters>>(params)
            joseCompliantSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(serialized)
                .shouldBe(params)
        }

        "DcApiUnsigned test $representation" {
            val parameters = verifierOid4vp.createPlainAuthnRequest(reqOptions)
            val authnRequest = RequestParametersFrom.OpenId4VpDcApiUnsigned(
                parameters = parameters,
                jsonString = joseCompliantSerializer.encodeToString(parameters),
                credentialIds = listOf("1"),
                callingPackageName = "com.example.app",
                callingOrigin = "https://example.com"
            )

            val params = holderOid4vp.startAuthorizationResponsePreparation(authnRequest).getOrThrow().request
                .shouldBeInstanceOf<RequestParametersFrom.OpenId4VpDcApiUnsigned>()

            val serialized =
                joseCompliantSerializer.encodeToString<RequestParametersFrom<AuthenticationRequestParameters>>(params)
            joseCompliantSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(serialized)
                .shouldBe(params)
        }

        "JwsSigned test $representation" {
            val authnRequestUrl = verifierOid4vp.createAuthnRequest(
                reqOptions, CreationOptions.SignedRequestByValue(walletUrl)
            ).getOrThrow().url

            val jarRequest: JarRequestParameters = Url(authnRequestUrl).encodedQuery.decodeFromUrlQuery()
            jarRequest.clientId shouldBe clientId
            val serializedRequest = jarRequest.request.shouldNotBeNull()
            val params = holderOid4vp.startAuthorizationResponsePreparation(serializedRequest).getOrThrow().request
                .shouldBeInstanceOf<RequestParametersFrom.Jws<AuthenticationRequestParameters>>()

            val serialized =
                joseCompliantSerializer.encodeToString<RequestParametersFrom<AuthenticationRequestParameters>>(params)
            joseCompliantSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(serialized)
                .shouldBe(params)
        }

        "DcApiSigned test $representation" {
            val authnRequestUrl = verifierOid4vp.createAuthnRequest(
                reqOptions, CreationOptions.SignedRequestByValue(walletUrl)
            ).getOrThrow().url

            val jarRequest: JarRequestParameters = Url(authnRequestUrl).encodedQuery.decodeFromUrlQuery()
            jarRequest.clientId shouldBe clientId
            val serializedRequest = jarRequest.request.shouldNotBeNull()
            val authnRequest = RequestParametersFrom.OpenId4VpDcApiSigned(
                jwsTyped = JwsTyped(serializedRequest),
                credentialIds = listOf("1"),
                callingPackageName = "com.example.app",
                callingOrigin = "https://example.com"
            )

            val params = holderOid4vp.startAuthorizationResponsePreparation(authnRequest).getOrThrow().request
                .shouldBeInstanceOf<RequestParametersFrom.OpenId4VpDcApiSigned>()

            val serialized =
                joseCompliantSerializer.encodeToString<RequestParametersFrom<AuthenticationRequestParameters>>(params)
            joseCompliantSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(serialized)
                .shouldBe(params)
        }

        "DcApiMultiSigned test $representation" {
            val authnRequestUrl = verifierOid4vp.createAuthnRequest(
                reqOptions, CreationOptions.SignedRequestByValue(walletUrl)
            ).getOrThrow().url

            val jarRequest: JarRequestParameters = Url(authnRequestUrl).encodedQuery.decodeFromUrlQuery()
            jarRequest.clientId shouldBe clientId
            val serializedRequest = jarRequest.request.shouldNotBeNull()
            val compactTyped = JwsTyped<AuthenticationRequestParameters>(serializedRequest)
            val authnRequest = RequestParametersFrom.OpenId4VpDcApiMultiSigned(
                jwsTyped = JwsTyped<AuthenticationRequestParameters>(listOf(compactTyped.jws.toJwsFlattened())),
                credentialIds = listOf("1"),
                callingPackageName = "com.example.app",
                callingOrigin = "https://example.com"
            )

            val params = holderOid4vp.startAuthorizationResponsePreparation(authnRequest).getOrThrow().request
                .shouldBeInstanceOf<RequestParametersFrom.OpenId4VpDcApiMultiSigned>()

            val serialized =
                joseCompliantSerializer.encodeToString<RequestParametersFrom<AuthenticationRequestParameters>>(params)
            joseCompliantSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(serialized)
                .shouldBe(params)
        }
    }
}

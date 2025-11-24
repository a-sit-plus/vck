package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catching
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.openid.ClientNonceResponse
import at.asitplus.openid.CredentialResponseParameters
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.TokenIntrospectionResponse
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.ValidatorSdJwt
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.extensions.supportedSdAlgorithms
import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oidvci.CredentialDataProviderFun
import at.asitplus.wallet.lib.oidvci.CredentialIssuer
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.openid.toOAuth2Error
import io.github.aakira.napier.Napier
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.engine.mock.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.random.Random
import kotlin.time.Clock

object TestUtils {

    fun MockRequestHandleScope.respondOAuth2Error(throwable: Throwable): HttpResponseData = respond(
        vckJsonSerializer.encodeToString<OAuth2Error>(throwable.toOAuth2Error(null)),
        headers = headers {
            append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            (throwable as? OAuth2Exception.UseDpopNonce)?.dpopNonce
                ?.let { append(HttpHeaders.DPoPNonce, it) }
        },
        status = HttpStatusCode.BadRequest
    ).also { Napier.w("Server error: ${throwable.message}", throwable) }

    fun HttpRequestData.toRequestInfo(): RequestInfo = RequestInfo(
        url = url.toString(),
        method = method,
        dpop = headers["DPoP"],
        clientAttestation = headers["OAuth-Client-Attestation"],
        clientAttestationPop = headers["OAuth-Client-Attestation-PoP"],
    )

    fun dummyUser(): OidcUserInfoExtended = OidcUserInfoExtended.deserialize("{\"sub\": \"foo\"}").getOrThrow()

    fun credentialDataProviderFun(
        scheme: ConstantIndex.CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
        attributes: Map<String, String>
    ): CredentialDataProviderFun = CredentialDataProviderFun {
        catching {
            require(it.credentialScheme == scheme)
            require(it.credentialRepresentation == representation)
            var digestId = 0u
            when (representation) {
                ConstantIndex.CredentialRepresentation.PLAIN_JWT -> TODO()
                ConstantIndex.CredentialRepresentation.SD_JWT -> CredentialToBeIssued.VcSd(
                    claims = attributes.map { ClaimToBeIssued(it.key, it.value) },
                    expiration = Clock.System.now(),
                    scheme = it.credentialScheme,
                    subjectPublicKey = it.subjectPublicKey,
                    userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject"))
                        .getOrThrow(),
                    sdAlgorithm = supportedSdAlgorithms.random()
                )

                ConstantIndex.CredentialRepresentation.ISO_MDOC -> CredentialToBeIssued.Iso(
                    attributes.map {
                        IssuerSignedItem(digestId++, Random.nextBytes(32), it.key, it.value)
                    },
                    Clock.System.now(),
                    it.credentialScheme,
                    it.subjectPublicKey,
                    OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
                )
            }
        }
    }

    suspend fun CredentialIssuanceResult.Success.verifySdJwtCredential(
        claimName: String,
        expectedClaimValue: String,
        credentialKey: CryptoPublicKey,
    ) {
        credentials.shouldBeSingleton().also {
            it.first().shouldBeInstanceOf<Holder.StoreCredentialInput.SdJwt>().also {
                it.scheme shouldBe EuPidScheme
                ValidatorSdJwt().verifySdJwt(it.signedSdJwtVc, credentialKey)
                    .shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessSdJwt>()
                    .disclosures.values.any {
                        it.claimName == claimName &&
                                it.claimValue.jsonPrimitive.content == expectedClaimValue
                    }
                    .shouldBeTrue()
            }
        }
    }

    fun CredentialIssuanceResult.Success.verifyIsoMdocCredential(
        claimName: String,
        expectedClaimValue: String,
    ) {
        credentials.shouldBeSingleton().also {
            it.first().shouldBeInstanceOf<Holder.StoreCredentialInput.Iso>().also {
                it.scheme shouldBe EuPidScheme
                it.issuerSigned.namespaces?.values?.flatMap { it.entries }?.map { it.value }
                    ?.any { it.elementIdentifier == claimName && it.elementValue == expectedClaimValue }
                    ?.shouldNotBeNull()?.shouldBeTrue()
            }
        }
    }

    fun MockRequestHandleScope.respond(result: PushedAuthenticationResponseParameters): HttpResponseData =
        respond(
            vckJsonSerializer.encodeToString<PushedAuthenticationResponseParameters>(result),
            headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
        )

    fun MockRequestHandleScope.respond(result: CredentialIssuer.CredentialResponse): HttpResponseData =
        when (result) {
            is CredentialIssuer.CredentialResponse.Encrypted -> respond(
                result.response.serialize(),
                headers = headersOf(HttpHeaders.ContentType, MediaTypes.Application.JWT)
            )

            is CredentialIssuer.CredentialResponse.Plain -> respond(
                vckJsonSerializer.encodeToString<CredentialResponseParameters>(result.response),
                headers = headersOf(HttpHeaders.ContentType, MediaTypes.Application.JSON)
            )
        }

    fun MockRequestHandleScope.respond(result: CredentialIssuer.Nonce): HttpResponseData = respond(
        vckJsonSerializer.encodeToString<ClientNonceResponse>(result.response),
        headers = headers {
            append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            result.dpopNonce?.let { set(HttpHeaders.DPoPNonce, it) }
        }
    )

    fun MockRequestHandleScope.respond(result: TokenResponseParameters): HttpResponseData = respond(
        vckJsonSerializer.encodeToString<TokenResponseParameters>(result),
        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
    )


    fun MockRequestHandleScope.respond(result: TokenIntrospectionResponse): HttpResponseData = respond(
        vckJsonSerializer.encodeToString<TokenIntrospectionResponse>(result),
        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
    )

    fun MockRequestHandleScope.respond(result: JsonObject): HttpResponseData = respond(
        vckJsonSerializer.encodeToString<JsonObject>(result),
        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
    )

    fun MockRequestHandleScope.respond(result: IssuerMetadata): HttpResponseData = respond(
        vckJsonSerializer.encodeToString<IssuerMetadata>(result),
        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
    )

    fun MockRequestHandleScope.respond(result: OAuth2AuthorizationServerMetadata): HttpResponseData = respond(
        vckJsonSerializer.encodeToString<OAuth2AuthorizationServerMetadata>(result),
        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
    )

}
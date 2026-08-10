package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catching
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.TokenIntrospectionJwtResponse
import at.asitplus.openid.TokenIntrospectionResponse
import at.asitplus.openid.TokenIntrospectionResult
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.eupid.EU_PID_DOCTYPE
import at.asitplus.wallet.eupidsdjwt.EU_PID_SD_JWT_VCT
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.ValidatorSdJwt
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.CredentialRepresentation
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList
import at.asitplus.wallet.lib.extensions.supportedSdAlgorithms
import at.asitplus.wallet.lib.oauth2.DPoPNonce
import at.asitplus.wallet.lib.oauth2.ResponseWithDpopNonce
import at.asitplus.wallet.lib.oidvci.CredentialDataProviderFun
import at.asitplus.wallet.lib.oidvci.CredentialIssuer
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
import kotlin.time.Duration.Companion.minutes

object TestUtils {

    fun MockRequestHandleScope.respondOAuth2Error(throwable: Throwable): HttpResponseData = respond(
        joseCompliantSerializer.encodeToString(throwable.toOAuth2Error(null)),
        headers = headers {
            append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            (throwable as? OAuth2Exception.UseDpopNonce)?.dpopNonce
                ?.let { append(HttpHeaders.DPoPNonce, it) }
        },
        status = HttpStatusCode.BadRequest
    ).also { Napier.w("Server error: ${throwable.message}", throwable) }

    fun dummyUser(): OidcUserInfoExtended = OidcUserInfoExtended.deserialize("{\"sub\": \"foo\"}").getOrThrow()

    fun credentialDataProviderFun(
        scheme: CredentialScheme,
        representation: CredentialRepresentation,
        attributes: Map<String, String>,
        revocationKind: RevocationList.Kind = RevocationList.Kind.STATUS_LIST,
    ): CredentialDataProviderFun = CredentialDataProviderFun {
        catching {
            require(it.credentialScheme == scheme)
            require(it.credentialRepresentation == representation)
            var digestId = 0u
            when (representation) {
                PLAIN_JWT -> TODO()
                SD_JWT -> CredentialToBeIssued.VcSd(
                    claims = attributes.map { ClaimToBeIssued(it.key, it.value) },
                    expiration = Clock.System.now().plus(1.minutes),
                    scheme = it.credentialScheme as SdJwtCredentialScheme,
                    subjectPublicKey = it.subjectPublicKey,
                    userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject"))
                        .getOrThrow(),
                    sdAlgorithm = supportedSdAlgorithms.random()
                )

                ISO_MDOC -> CredentialToBeIssued.Iso(
                    issuerSignedItems = attributes.map {
                        IssuerSignedItem(digestId++, Random.nextBytes(32), it.key, it.value)
                    },
                    expiration = Clock.System.now().plus(1.minutes),
                    scheme = it.credentialScheme as IsoMdocCredentialScheme,
                    subjectPublicKey = it.subjectPublicKey,
                    userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
                    revocationKind = revocationKind,
                )
            }
        }
    }

    suspend fun CredentialIssuanceResult.Success.verifySdJwtCredential(
        claimName: String,
        expectedClaimValue: String,
        credentialKey: CryptoPublicKey,
    ) {
        val euPidSdJwtScheme = AttributeIndex.resolveIdentifier(EU_PID_SD_JWT_VCT, SD_JWT)
        credentials.shouldBeSingleton().also {
            it.first().shouldBeInstanceOf<Holder.StoreCredentialInput.SdJwt>().also {
                it.scheme shouldBe euPidSdJwtScheme
                ValidatorSdJwt().verifySdJwt(it.signedSdJwtVc, credentialKey).getOrThrow()
                    .disclosures.values.any {
                        it.claimName == claimName &&
                                it.claimValue.jsonPrimitive.content == expectedClaimValue
                    }
                    .shouldBeTrue()
            }
        }
    }

    suspend fun CredentialIssuanceResult.Success.verifyIsoMdocCredential(
        claimName: String,
        expectedClaimValue: String,
    ) {
        val euPidScheme = AttributeIndex.resolveIdentifier(EU_PID_DOCTYPE, ISO_MDOC)
        credentials.shouldBeSingleton().also {
            it.first().shouldBeInstanceOf<Holder.StoreCredentialInput.Iso>().also {
                it.scheme shouldBe euPidScheme
                it.issuerSigned.namespaces?.values?.flatMap { it.entries }?.map { it.value }
                    ?.any { it.elementIdentifier == claimName && it.elementValue == expectedClaimValue }
                    ?.shouldNotBeNull()?.shouldBeTrue()
            }
        }
    }

    fun MockRequestHandleScope.respond(
        result: PushedAuthenticationResponseParameters
    ): HttpResponseData = respond(
        joseCompliantSerializer.encodeToString(result),
        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
    )

    fun MockRequestHandleScope.respond(result: CredentialIssuer.CredentialResponse): HttpResponseData =
        when (result) {
            is CredentialIssuer.CredentialResponse.Encrypted -> respond(
                result.response.serialize(),
                headers = headersOf(HttpHeaders.ContentType, MediaTypes.Application.JWT)
            )

            is CredentialIssuer.CredentialResponse.Plain -> respond(
                joseCompliantSerializer.encodeToString(result.response),
                headers = headersOf(HttpHeaders.ContentType, MediaTypes.Application.JSON)
            )
        }

    fun MockRequestHandleScope.respond(result: CredentialIssuer.Nonce): HttpResponseData =
        respondIncludingDpopNonce(ResponseWithDpopNonce(result.response, result.dpopNonce))

    inline fun <reified T> MockRequestHandleScope.respondIncludingDpopNonce(
        result: ResponseWithDpopNonce<T>
    ): HttpResponseData = respond(
        joseCompliantSerializer.encodeToString(result.response),
        headers = headers {
            append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            result.dpopNonce?.let { set(HttpHeaders.DPoPNonce, it) }
        }
    )

    fun MockRequestHandleScope.respond(result: TokenResponseParameters): HttpResponseData = respond(
        joseCompliantSerializer.encodeToString<TokenResponseParameters>(result),
        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
    )

    fun MockRequestHandleScope.respond(result: TokenIntrospectionResult): HttpResponseData = when (result) {
        is TokenIntrospectionResponse -> respond(result)
        is TokenIntrospectionJwtResponse -> respond(
            joseCompliantSerializer.encodeToString<TokenIntrospectionJwtResponse>(result),
            headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
        )
    }

    fun MockRequestHandleScope.respond(result: TokenIntrospectionResponse): HttpResponseData = respond(
        joseCompliantSerializer.encodeToString(result),
        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
    )

    fun MockRequestHandleScope.respond(result: JsonObject): HttpResponseData = respond(
        joseCompliantSerializer.encodeToString(result),
        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
    )

    fun MockRequestHandleScope.respond(result: IssuerMetadata): HttpResponseData = respond(
        joseCompliantSerializer.encodeToString(result),
        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
    )

    fun MockRequestHandleScope.respond(result: OAuth2AuthorizationServerMetadata): HttpResponseData = respond(
        joseCompliantSerializer.encodeToString(result),
        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
    )

}

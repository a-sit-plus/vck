package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catching
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.wallet.eupid.EU_PID_DOCTYPE
import at.asitplus.wallet.eupidsdjwt.EU_PID_SD_JWT_VCT
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.ValidatorSdJwt
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.CredentialRepresentation
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList
import at.asitplus.wallet.lib.extensions.supportedSdAlgorithms
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.oauth2.toHttpResponse
import at.asitplus.wallet.lib.oauth2.toResourceServerHttpResponse
import at.asitplus.wallet.lib.oidvci.CredentialDataProviderFun
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.ReceivedCredential
import at.asitplus.wallet.lib.validation.CredentialValidationInput
import io.github.aakira.napier.Napier
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import at.asitplus.wallet.lib.PreparedHttpResponse
import io.ktor.client.engine.mock.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.json.jsonPrimitive
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

object TestUtils {

    /** Writes out [response], as converted by a server, e.g. with `toHttpResponse()` or `directPostHttpResponse()`. */
    fun MockRequestHandleScope.respond(response: PreparedHttpResponse): HttpResponseData = respond(
        content = response.body?.text.orEmpty(),
        status = response.status,
        headers = Headers.build {
            appendAll(response.headers)
            response.body?.let { append(HttpHeaders.ContentType, it.contentType.toString()) }
        },
    )

    /**
     * Error response of an authorization server endpoint, see [OAuth2Exception.toHttpResponse], or 500 for anything
     * that is not an [OAuth2Exception].
     */
    fun MockRequestHandleScope.respondOAuth2Error(throwable: Throwable): HttpResponseData =
        respondConverted(throwable) { toHttpResponse() }

    /**
     * Error response of a resource endpoint accessed with [authorizationHeader] (credential, userinfo), see
     * [OAuth2Exception.toResourceServerHttpResponse], or 500 for anything that is not an [OAuth2Exception].
     */
    fun MockRequestHandleScope.respondResourceServerError(
        throwable: Throwable,
        authorizationHeader: String?,
    ): HttpResponseData = respondConverted(throwable) { toResourceServerHttpResponse(authorizationHeader) }

    private fun MockRequestHandleScope.respondConverted(
        throwable: Throwable,
        convert: OAuth2Exception.() -> PreparedHttpResponse,
    ): HttpResponseData {
        Napier.w("Server error: ${throwable.message}", throwable)
        return (throwable as? OAuth2Exception)?.let { respond(it.convert()) }
            ?: respondError(HttpStatusCode.InternalServerError)
    }

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
        scheme shouldBe AttributeIndex.resolveIdentifier(EU_PID_SD_JWT_VCT, SD_JWT)
        val input = receivedCredentials.shouldBeSingleton().first()
            .shouldBeInstanceOf<ReceivedCredential.Decoded>().input
            .shouldBeInstanceOf<CredentialValidationInput.SdJwtVc>()
        ValidatorSdJwt().verifySdJwt(SdJwtSigned.parseCatching(input.compact).getOrThrow(), credentialKey).getOrThrow()
            .disclosures.values.any {
                it.claimName == claimName &&
                        it.claimValue.jsonPrimitive.content == expectedClaimValue
            }
            .shouldBeTrue()
    }

    /** Verifies the only credential, an mdoc of the EU PID, carries [claimName], and returns it. */
    suspend fun CredentialIssuanceResult.Success.verifyIsoMdocCredential(
        claimName: String,
        expectedClaimValue: String,
    ): IssuerSigned {
        scheme shouldBe AttributeIndex.resolveIdentifier(EU_PID_DOCTYPE, ISO_MDOC)
        val input = receivedCredentials.shouldBeSingleton().first()
            .shouldBeInstanceOf<ReceivedCredential.Decoded>().input
            .shouldBeInstanceOf<CredentialValidationInput.IsoMdoc>()
        return coseCompliantSerializer.decodeFromByteArray<IssuerSigned>(input.issuerSignedCbor).also {
            it.namespaces?.values?.flatMap { it.entries }?.map { it.value }
                ?.any { it.elementIdentifier == claimName && it.elementValue == expectedClaimValue }
                ?.shouldNotBeNull()?.shouldBeTrue()
        }
    }

}

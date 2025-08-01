package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_AUTHORIZATION_CODE
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_CODE
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_BEARER
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.data.vckJsonSerializer
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.ktor.http.*
import kotlinx.serialization.json.JsonPrimitive
import kotlin.random.Random
import kotlin.time.Duration.Companion.seconds


class SerializationTest : FunSpec({

    fun createAuthorizationRequest() = AuthenticationRequestParameters(
        responseType = GRANT_TYPE_CODE,
        clientId = randomString(),
        authorizationDetails = setOf(
            OpenIdAuthorizationDetails(
                format = CredentialFormatEnum.JWT_VC,
                credentialDefinition = SupportedCredentialFormatDefinition(
                    types = setOf(VERIFIABLE_CREDENTIAL, randomString()),
                ),
                credentialIdentifiers = setOf(randomString()),
            )
        ),
        redirectUrl = randomString(),
        scope = randomString(),
        walletIssuer = randomString(),
        userHint = randomString(),
        issuerState = randomString()
    )

    fun createTokenRequest() = TokenRequestParameters(
        grantType = GRANT_TYPE_AUTHORIZATION_CODE,
        code = randomString(),
        redirectUrl = "https://wallet.a-sit.at/app/${randomString()}",
        clientId = randomString(),
        preAuthorizedCode = randomString(),
        codeVerifier = randomString(),
    )

    fun createTokenResponse() = TokenResponseParameters(
        accessToken = randomString(),
        refreshToken = randomString(),
        tokenType = TOKEN_TYPE_BEARER,
        expires = Random.nextInt(1, Int.MAX_VALUE).seconds,
        scope = randomString(),
        authorizationPending = false,
        interval = Random.nextInt(1, Int.MAX_VALUE).seconds,
    )

    fun createCredentialRequest() = CredentialRequestParameters(
        credentialIdentifier = randomString(),
        credentialConfigurationId = randomString(),
        credentialDefinition = SupportedCredentialFormatDefinition(
            types = setOf(randomString(), randomString()),
        ),
        proof = CredentialRequestProof(
            proofType = OpenIdConstants.ProofType.Other(randomString()),
            jwt = randomString()
        )
    )

    fun createCredentialResponse() = CredentialResponseParameters(
        credentials = setOf(CredentialResponseSingleCredential(JsonPrimitive(randomString()))),
        acceptanceToken = randomString(),
        clientNonce = randomString(),
        clientNonceExpiresIn = Random.nextInt(1, Int.MAX_VALUE).seconds,
    )

    test("createAuthorizationRequest as GET") {
        val params = createAuthorizationRequest()
        val baseUrl = "https://wallet.a-sit.at/authorize"

        val intermediateMap = params.encodeToParameters()
        val url = "$baseUrl?${intermediateMap.formUrlEncode()}"

        url shouldContain baseUrl
        url shouldContain "response_type=${params.responseType}"
        url shouldContain "client_id=${params.clientId}"
        val parsed: AuthenticationRequestParameters = intermediateMap.decode()
        parsed shouldBe params
    }

    test("createAuthorizationRequest as POST") {
        val params = createAuthorizationRequest()
        val intermediateMap = params.encodeToParameters()
        val formEncoded = intermediateMap.formUrlEncode()

        formEncoded shouldContain "response_type=${params.responseType}"
        formEncoded shouldContain "client_id=${params.clientId}"
        formEncoded shouldContain "authorization_details=" + "[{\"type\":".encodeURLParameter()
        val parsed: AuthenticationRequestParameters = intermediateMap.decode()
        parsed shouldBe params
        val parsedToo: AuthenticationRequestParameters = formEncoded.decodeFromPostBody()
        parsedToo shouldBe params
    }

    test("createTokenRequest as POST") {
        val params = createTokenRequest()
        val intermediateMap = params.encodeToParameters()
        val formEncoded = intermediateMap.formUrlEncode()

        val parsed: TokenRequestParameters = intermediateMap.decode()
        parsed shouldBe params
        val parsedToo: TokenRequestParameters = formEncoded.decodeFromPostBody()
        parsedToo shouldBe params
    }

    test("createTokenResponse as JSON") {
        val params = createTokenResponse()

        val json = vckJsonSerializer.encodeToString(params)

        json shouldContain "\"access_token\":"
        json shouldContain "\"token_type\":"
        json shouldContain "\"expires_in\":"
        val parsed: TokenResponseParameters = vckJsonSerializer.decodeFromString(json)
        parsed shouldBe params
    }

    test("createCredentialRequest as JSON") {
        val params = createCredentialRequest()

        val json = vckJsonSerializer.encodeToString(params)

        json shouldContain "\"type\":["
        json shouldContain "\"${params.credentialDefinition?.types?.first()}\""
        val parsed: CredentialRequestParameters =
            vckJsonSerializer.decodeFromString<CredentialRequestParameters>(json)
        parsed shouldBe params
    }

    test("createCredentialResponse as JSON") {
        val params = createCredentialResponse()

        val json = vckJsonSerializer.encodeToString(params)

        val parsed = vckJsonSerializer.decodeFromString<CredentialResponseParameters>(json)
        parsed shouldBe params
    }
})

val charPool = ('A'..'Z') + ('a'..'z') + ('0'..'9')

fun randomString() = (1..16)
    .map { Random.nextInt(0, charPool.size).let { charPool[it] } }
    .joinToString("")

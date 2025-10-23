package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.CredentialResponseParameters
import at.asitplus.openid.CredentialResponseSingleCredential
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_AUTHORIZATION_CODE
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_CODE
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_BEARER
import at.asitplus.openid.SupportedCredentialFormatDefinition
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.data.vckJsonSerializer
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.ktor.http.*
import kotlinx.serialization.json.JsonPrimitive
import kotlin.random.Random
import kotlin.time.Duration.Companion.seconds


val SerializationTest by testSuite {

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
        issuerState = randomString(),
        dcqlQuery = DCQLQuery(
            credentials = DCQLCredentialQueryList(
                DCQLSdJwtCredentialQuery(
                    id = DCQLCredentialQueryIdentifier(uuid4().toString()),
                    format = CredentialFormatEnum.DC_SD_JWT,
                    meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(vctValues = listOf(randomString())),
                )
            )
        )
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

    fun createCredentialResponse() = CredentialResponseParameters(
        credentials = setOf(CredentialResponseSingleCredential(JsonPrimitive(randomString()))),
        transactionId = randomString(),
        notificationId = randomString(),
    )

    test("createAuthorizationRequest as GET") {
        val params = createAuthorizationRequest()
        val baseUrl = "https://wallet.a-sit.at/authorize"
        val intermediateMap = params.encodeToParameters()

        "$baseUrl?${intermediateMap.formUrlEncode()}".apply {
            this shouldContain baseUrl
            this shouldContain "response_type=${params.responseType}"
            this shouldContain "client_id=${params.clientId}"
            this shouldContain "dcql_query=" + "{\"credentials".encodeURLParameter()
        }

        intermediateMap.decode<AuthenticationRequestParameters>() shouldBe params
    }

    test("createAuthorizationRequest as POST") {
        val params = createAuthorizationRequest()
        val intermediateMap = params.encodeToParameters()
        val formEncoded = intermediateMap.formUrlEncode().apply {
            this shouldContain "response_type=${params.responseType}"
            this shouldContain "client_id=${params.clientId}"
            this shouldContain "authorization_details=" + "[{\"type\":".encodeURLParameter()
            this shouldContain "dcql_query=" + "{\"credentials".encodeURLParameter()
        }

        intermediateMap.decode<AuthenticationRequestParameters>() shouldBe params

        formEncoded.decodeFromPostBody<AuthenticationRequestParameters>() shouldBe params
    }

    test("createTokenRequest as POST") {
        val params = createTokenRequest()
        val intermediateMap = params.encodeToParameters()
        val formEncoded = intermediateMap.formUrlEncode()

        intermediateMap.decode<TokenRequestParameters>() shouldBe params
        formEncoded.decodeFromPostBody<TokenRequestParameters>() shouldBe params
    }

    test("createTokenResponse as JSON") {
        val params = createTokenResponse()

        val json = vckJsonSerializer.encodeToString(params).apply {
            this shouldContain "\"access_token\":"
            this shouldContain "\"token_type\":"
            this shouldContain "\"expires_in\":"
        }
        vckJsonSerializer.decodeFromString<TokenResponseParameters>(json) shouldBe params
    }

    test("createCredentialResponse as JSON") {
        val params = createCredentialResponse()

        val json = vckJsonSerializer.encodeToString(params)

        vckJsonSerializer.decodeFromString<CredentialResponseParameters>(json) shouldBe params
    }
}
val charPool = ('A'..'Z') + ('a'..'z') + ('0'..'9')

fun randomString() = (1..16)
    .map { Random.nextInt(0, charPool.size).let { charPool[it] } }
    .joinToString("")

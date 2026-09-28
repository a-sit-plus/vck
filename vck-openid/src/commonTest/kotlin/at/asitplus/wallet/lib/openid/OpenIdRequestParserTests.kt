package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.encodeToParameters
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RemoteResourceRetrieverInput
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlinx.serialization.SerializationException
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject

/**
 * [RequestParser] turns every form in which an OpenID4VP authorization request can reach the wallet into
 * [RequestParametersFrom]: parameters in the URL, a JSON body, or a request object (RFC 9101) passed directly, by
 * value in `request`, or by reference in `request_uri`. Validating the parsed request is up to
 * [AuthorizationRequestValidator]; here we only check that parsing preserves the request, and rejects request objects
 * that OpenID4VP 1.0 and RFC 9101 forbid wallets to process.
 *
 * Encrypted request objects and `wallet_nonce` are covered in [OpenId4VpEncryptedRequestTest].
 */
val OpenIdRequestParserTests by matrixSuite {

    val requestUri = "https://verifier.example.com/request/1234567890"
    val authnRequest = AuthenticationRequestParameters(
        responseType = OpenIdConstants.VP_TOKEN,
        clientId = "x509_san_dns:verifier.example.com",
        responseMode = OpenIdConstants.ResponseMode.DirectPost,
        responseUrl = "https://verifier.example.com/response",
        nonce = "n-0S6_WzA2Mj",
        state = "af0ifjsldkj",
        // a structured parameter, so it has to survive the JSON-in-form encoding of URL parameters
        dcqlQuery = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(AtomicAttribute2023, SD_JWT)
        ).toDCQLRequest().shouldNotBeNull().dcqlQuery,
    )

    fun byValue(requestObject: String) = URLBuilder("https://wallet.example.com").apply {
        parameters.append("client_id", authnRequest.clientId!!)
        parameters.append("request", requestObject)
    }.buildString()

    val byReference = URLBuilder("https://wallet.example.com").apply {
        parameters.append("client_id", authnRequest.clientId!!)
        parameters.append("request_uri", requestUri)
    }.buildString()

    /** A parser that fetches [content] from [requestUri], and nothing from anywhere else. */
    fun parserServing(content: String) = RequestParser(
        remoteResourceRetriever = { if (it.url == requestUri) content else null }
    )

    testSuite("parameters in the URL") {
        "are parsed from the query" {
            val input = URLBuilder("https://wallet.example.com").apply {
                authnRequest.encodeToParameters().forEach { parameters.append(it.key, it.value) }
            }.buildString()

            RequestParser().parseRequestParameters(input).getOrThrow()
                .shouldBeInstanceOf<RequestParametersFrom.Uri<*>>().apply {
                    url.toString() shouldBe input
                    shouldCarry(authnRequest)
                }
        }

        "keep JSON-shaped values of string parameters as strings" {
            val input = "https://wallet.example.com?client_id=client&state=%7B%7D&nonce=%5B&user_hint=null"

            RequestParser().parseRequestParameters(input).getOrThrow().parameters shouldBe
                    AuthenticationRequestParameters(clientId = "client", state = "{}", nonce = "[", userHint = "null")
        }

        "ignore unknown parameters with malformed JSON values" {
            val input = "https://wallet.example.com?client_id=client&extension=%7B"

            RequestParser().parseRequestParameters(input).getOrThrow().parameters shouldBe
                    AuthenticationRequestParameters(clientId = "client")
        }
    }

    "JSON body is parsed" {
        val input = joseCompliantSerializer.encodeToString(authnRequest)

        RequestParser().parseRequestParameters(input).getOrThrow()
            .shouldBeInstanceOf<RequestParametersFrom.Json<*>>().apply {
                jsonString shouldBe input
                shouldCarry(authnRequest)
            }
    }

    testSuite("signed request object") {
        "passed directly is parsed" {
            val requestObject = signRequestObject(authnRequest)

            RequestParser().parseRequestParameters(requestObject).getOrThrow()
                .shouldBeInstanceOf<RequestParametersFrom.Jws<*>>().apply {
                    jws.toString() shouldBe requestObject
                    parent shouldBe null
                    shouldCarry(authnRequest)
                }
        }

        "by value in `request` is parsed" {
            val requestObject = signRequestObject(authnRequest)
            val input = byValue(requestObject)

            RequestParser().parseRequestParameters(input).getOrThrow()
                .shouldBeInstanceOf<RequestParametersFrom.Jws<*>>().apply {
                    jws.toString() shouldBe requestObject
                    parent.toString() shouldBe input
                    shouldCarry(authnRequest)
                }
        }

        "by reference in `request_uri` is fetched with GET and parsed" {
            // OpenID4VP 1.0, 5.10: `request_uri_method` defaults to `get`, and the wallet asks for a request object
            val requestObject = signRequestObject(authnRequest)
            var fetched: RemoteResourceRetrieverInput? = null
            val parser = RequestParser(
                remoteResourceRetriever = { fetched = it; requestObject }
            )

            parser.parseRequestParameters(byReference).getOrThrow()
                .shouldBeInstanceOf<RequestParametersFrom.Jws<*>>().apply {
                    jws.toString() shouldBe requestObject
                    parent.toString() shouldBe byReference
                    shouldCarry(authnRequest)
                }
            fetched.shouldNotBeNull().apply {
                url shouldBe requestUri
                method shouldBe HttpMethod.Get
                headers[HttpHeaders.Accept] shouldBe MediaTypes.Application.AUTHZ_REQ_JWT
            }
        }
    }

    testSuite("request object is rejected") {
        // OpenID4VP 1.0, 5: "Wallets MUST NOT process Request Objects where the typ Header Parameter is not present
        // or does not have the value oauth-authz-req+jwt"
        testSuite("without typ oauth-authz-req+jwt") {
            listOf(null, "JWT", "jwt").asData(nameFn = { it ?: "no typ" }) test { typ ->
                RequestParser().parseRequestParameters(signRequestObject(authnRequest, typ = typ))
                    .exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
                    .message.shouldNotBeNull() shouldContain JwsContentTypeConstants.OAUTH_AUTHZ_REQUEST
            }
        }

        // RFC 9101, 4 admits only signed, or signed and encrypted, request objects
        "when plain in `request`" {
            val input = byValue(joseCompliantSerializer.encodeToString(authnRequest))

            RequestParser().parseRequestParameters(input)
                .exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
        }

        // OpenID4VP 1.0, 5.10.1: the request URI response is "a signed, optionally encrypted, request object"
        "when plain at `request_uri`" {
            parserServing(joseCompliantSerializer.encodeToString(authnRequest))
                .parseRequestParameters(byReference)
                .exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
        }

        // an unresolved JAR request must not pass for a parsed authorization request without any parameters
        "when it can not be retrieved from `request_uri`" {
            RequestParser().parseRequestParameters(byReference)
                .exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
                .message.shouldNotBeNull() shouldContain requestUri
        }

        // RFC 9101, 6.2: a request object must not contain `request` or `request_uri` itself
        "when it nests another `request_uri`" {
            val nested = JarRequestParameters(
                clientId = authnRequest.clientId!!,
                requestUri = "https://verifier.example.com/request/nested",
            )

            parserServing(signRequestObject<RequestParameters>(nested, RequestParameters.serializer()))
                .parseRequestParameters(byReference)
                .exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
                .message.shouldNotBeNull() shouldContain "request_uri"
        }

        "when its payload is not a request, keeping the serialization error as cause" {
            val invalid = JsonObject(mapOf("response_type" to JsonArray(emptyList())))

            parserServing(signRequestObject(invalid, JsonObject.serializer()))
                .parseRequestParameters(byReference)
                .exceptionOrNull().shouldBeInstanceOf<InvalidRequest>()
                .cause.shouldBeInstanceOf<SerializationException>()
                .message.shouldNotBeNull() shouldContain "response_type"
        }
    }
}

private suspend fun signRequestObject(
    payload: AuthenticationRequestParameters,
    typ: String? = JwsContentTypeConstants.OAUTH_AUTHZ_REQUEST,
): String = signRequestObject(payload, AuthenticationRequestParameters.serializer(), typ)

private suspend fun <P : Any> signRequestObject(
    payload: P,
    serializer: SerializationStrategy<P>,
    typ: String? = JwsContentTypeConstants.OAUTH_AUTHZ_REQUEST,
): String = SignJwt<P>(EphemeralKeyWithoutCert(), JwsHeaderNone())(typ, payload, serializer).getOrThrow().toString()

/**
 * Asserts the parsed request carries [expected], and survives serialization, as wallets persist it between preparing
 * and finalizing the authorization response.
 */
private fun RequestParametersFrom<*>.shouldCarry(expected: AuthenticationRequestParameters) {
    parameters shouldBe expected
    val typed = shouldBeInstanceOf<RequestParametersFrom<AuthenticationRequestParameters>>()
    joseCompliantSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(
        joseCompliantSerializer.encodeToString(typed)
    ) shouldBe typed
}

package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json

/**
 * `OpenId4VpHolder` can only process authorization requests, but the request parser may well return something else,
 * e.g. an unresolved JAR request, or an RQES signature request. Since the generic argument of `RequestParametersFrom`
 * is erased, such requests used to pass the cast in `OpenId4VpHolder.parse` and fail with a `ClassCastException`
 * ("JarRequestParameters cannot be cast to AuthenticationRequestParameters") somewhere inside request validation.
 */
val OpenId4VpHolderRequestParsingTest by matrixSuite {

    val requestUri = "https://example.com/request/1234"

    listOf(
        emptyList(),
        listOf("not-base64!"),
        listOf("{".encodeToByteArray().encodeToString(Base64UrlStrict)),
        listOf("""{"type":"unknown"}""".encodeToByteArray().encodeToString(Base64UrlStrict)),
    ).asData(
        nameFn = { "Malformed transaction_data is rejected during preparation: $it" },
    ) test { entries ->
        val input = """{
            "response_type": "vp_token",
            "client_id": "https://verifier.example.org",
            "nonce": "transaction-nonce",
            "transaction_data": ${Json.encodeToString(entries)}
        }""".trimIndent()
        Json.decodeFromString<AuthenticationRequestParameters>(input)
        val error = OpenId4VpHolder().startAuthorizationResponsePreparation(input)
            .exceptionOrNull().shouldNotBeNull().shouldBeInstanceOf<OAuth2Exception.InvalidTransactionData>()
        error.error shouldBe "invalid_transaction_data"
        error.cause.shouldNotBeNull()
    }

    // CSC permits omission only when the surrounding protocol does not require credential_ids.
    // OpenID4VP 1.0 sections 5.1 and 8.5 require valid, non-empty references before user consent or signing.
    listOf(null, "[]", "[\"unknown-query\"]").asData(
        nameFn = { ids -> "QES approval with invalid credential_ids is rejected during preparation: $ids" },
    ) test { ids ->
        val encoded = """{
            "type": "https://cloudsignatureconsortium.org/2025/qes-approval",
            ${ids?.let { "\"credential_ids\": $it," }.orEmpty()}
            "signatureQualifier": "eu_eidas_qes",
            "numSignatures": 1,
            "documentDigests": [{ "label": "Contract", "hash": "AQID" }],
            "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
        }""".trimIndent().encodeToByteArray().encodeToString(Base64UrlStrict)
        val input = """{
            "response_type": "vp_token",
            "client_id": "https://verifier.example.org",
            "nonce": "approval-nonce",
            "dcql_query": {
                "credentials": [{
                    "id": "approval-credential", "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["AtomicAttribute2023"] }
                }]
            },
            "transaction_data": ["$encoded"]
        }""".trimIndent()
        // Parsing the model permits CSC's conditional omission; the OpenID protocol boundary rejects it.
        Json.decodeFromString<AuthenticationRequestParameters>(input)
        val error = OpenId4VpHolder().startAuthorizationResponsePreparation(input)
            .exceptionOrNull().shouldNotBeNull().shouldBeInstanceOf<OAuth2Exception.InvalidTransactionData>()
        error.error shouldBe "invalid_transaction_data"
        error.cause.shouldNotBeNull().message.shouldNotBeNull() shouldContain "credential_ids"
    }

    listOf(null, "[]", "[\"unknown-query\"]").asData(
        nameFn = { ids -> "X.509 QES request with invalid credential_ids is rejected during preparation: $ids" },
    ) test { ids ->
        val encoded = """{
            "type":"https://cloudsignatureconsortium.org/2025/qes",
            ${ids?.let { "\"credential_ids\": $it," }.orEmpty()}
            "signatureRequests":[{
                "href":"https://example.test/contract.pdf", "signatureQualifier":"eu_eidas_qes"
            }]
        }""".encodeToByteArray().encodeToString(Base64UrlStrict)
        val input = """{
            "response_type":"vp_token", "client_id":"https://verifier.example.org", "nonce":"qes-nonce",
            "dcql_query":{"credentials":[{
                "id":"certificate", "format":"https://cloudsignatureconsortium.org/2025/x509", "meta":{}
            }]},
            "transaction_data":["$encoded"]
        }"""
        Json.decodeFromString<AuthenticationRequestParameters>(input)
        OpenId4VpHolder().startAuthorizationResponsePreparation(input)
            .exceptionOrNull().shouldNotBeNull().shouldBeInstanceOf<OAuth2Exception.InvalidTransactionData>()
            .cause.shouldNotBeNull().message.shouldNotBeNull() shouldContain "credential_ids"
    }

    "request_uri that can not be retrieved is rejected" {
        // The retriever answers nothing, e.g. because the fetch failed, or because the verifier put a URL into
        // `request_uri` that the wallet does not handle: either way there is no request object to process
        val holder = OpenId4VpHolder(remoteResourceRetriever = { null })
        val input = URLBuilder("https://example.com/wallet").apply {
            parameters.append("client_id", "https://example.com")
            parameters.append("request_uri", requestUri)
        }.buildString()

        holder.startAuthorizationResponsePreparation(input)
            .exceptionOrNull().shouldNotBeNull()
            .shouldBeInstanceOf<OAuth2Exception.InvalidRequest>()
            .message.shouldNotBeNull() shouldContain requestUri

        holder.createAuthnResponse(input)
            .exceptionOrNull().shouldNotBeNull()
            .shouldBeInstanceOf<OAuth2Exception.InvalidRequest>()
            .message.shouldNotBeNull() shouldContain requestUri
    }

    "request that is not an authorization request is rejected" {
        // A request for remote signature creation (RQES), which is parsed into `SignatureRequestParameters`
        val input = """
            {
              "response_type": "sign_response",
              "client_id": "ff008dbe-0a00-43aa-8cbd-57b44fbd8cf9",
              "response_mode": "direct_post",
              "response_uri": "https://example.com/wallet/sd/upload",
              "nonce": "SD6caM6K17zn6lnvVlu9FQ92Je2rWg-rqbMegL1CBIY",
              "signatureQualifier": "eu_eidas_qes",
              "documentDigests": [
                { "hash": "dbe822af4b1cfddea8e8526a04a46557074d093cb02fee0f3dcc5f323629504e", "label": "sample.pdf" }
              ],
              "documentLocations": [
                { "uri": "https://example.com/rp/document/sample.pdf", "method": { "type": "public" } }
              ],
              "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
            }
        """.replace("\n", "").trimIndent()

        OpenId4VpHolder().startAuthorizationResponsePreparation(input)
            .exceptionOrNull().shouldNotBeNull()
            .shouldBeInstanceOf<OAuth2Exception.InvalidRequest>()
            .message.shouldNotBeNull() shouldContain "SignatureRequestParameters"
    }
}

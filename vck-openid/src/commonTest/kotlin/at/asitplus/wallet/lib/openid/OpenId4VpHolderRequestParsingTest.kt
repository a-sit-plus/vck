package at.asitplus.wallet.lib.openid

import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*

/**
 * `OpenId4VpHolder` can only process authorization requests, but the request parser may well return something else,
 * e.g. an unresolved JAR request, or an RQES signature request. Since the generic argument of `RequestParametersFrom`
 * is erased, such requests used to pass the cast in `OpenId4VpHolder.parse` and fail with a `ClassCastException`
 * ("JarRequestParameters cannot be cast to AuthenticationRequestParameters") somewhere inside request validation.
 */
val OpenId4VpHolderRequestParsingTest by matrixSuite {

    val requestUri = "https://example.com/request/1234"

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

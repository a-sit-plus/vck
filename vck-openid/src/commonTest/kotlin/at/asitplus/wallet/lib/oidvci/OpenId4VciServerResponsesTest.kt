package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.ClientNonceResponse
import at.asitplus.openid.CredentialResponseParameters
import at.asitplus.openid.IssuerMetadata
import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.oauth2.AuthorizationServerFixture
import at.asitplus.wallet.lib.oauth2.DPoPNonce
import io.kotest.matchers.shouldBe
import io.ktor.http.*

val OpenId4VciServerResponsesTest by matrixSuite {

    testSuite("issuer metadata content negotiation") {
        val signed = "signed"
        val unsigned = "unsigned"
        mapOf(
            null to unsigned,
            "" to unsigned,
            "application/json" to unsigned,
            "*/*" to unsigned,
            "application/*" to unsigned,
            "application/jwt" to signed,
            "APPLICATION/JWT" to signed,
            "application/jwt; charset=UTF-8" to signed,
            "application/json, application/jwt" to signed,
            "application/jwt;q=0.5, application/json" to unsigned,
            "application/jwt, application/json;q=0.5" to signed,
            "application/jwt;q=0.5, */*;q=0.1" to signed,
            "application/jwt;q=0" to unsigned,
            "text/html, application/jwt;q=0.9, */*;q=0.8" to signed,
        ).entries.asData(nameFn = { (accept, expected) -> "${accept ?: "no Accept"}: $expected" }) test
                { (accept, expected) ->
                    val server = AuthorizationServerFixture(requirePAR = false).openId4VciServer

                    server.metadataHttpResponse(accept).getOrThrow().apply {
                        status shouldBe HttpStatusCode.OK
                        headers[HttpHeaders.Vary] shouldBe HttpHeaders.Accept
                        if (expected == signed) {
                            headers[HttpHeaders.ContentType] shouldBe MediaTypes.Application.JWT
                            JwsCompactTyped<IssuerMetadata>(body).payload.credentialIssuer shouldBe
                                    server.metadata.credentialIssuer
                        } else {
                            headers[HttpHeaders.ContentType] shouldBe MediaTypes.Application.JSON
                            joseCompliantSerializer.decodeFromString<IssuerMetadata>(body) shouldBe server.metadata
                        }
                    }
                }
    }

    testSuite("nonce response") {
        val nonce = ClientNonceResponse("client-nonce")

        test("is not cached, with fresh DPoP nonce") {
            OpenId4VciServer.Nonce(nonce, "dpop-nonce").toHttpResponse().apply {
                status shouldBe HttpStatusCode.OK
                headers[HttpHeaders.ContentType] shouldBe MediaTypes.Application.JSON
                headers[HttpHeaders.CacheControl] shouldBe "no-store"
                headers[HttpHeaders.DPoPNonce] shouldBe "dpop-nonce"
                joseCompliantSerializer.decodeFromString<ClientNonceResponse>(body) shouldBe nonce
            }
        }

        test("without DPoP nonce") {
            OpenId4VciServer.Nonce(nonce).toHttpResponse().headers.names() shouldBe
                    setOf(HttpHeaders.ContentType, HttpHeaders.CacheControl)
        }
    }

    testSuite("credential response") {
        test("plain as JSON, not cached") {
            val response = CredentialResponseParameters(transactionId = "transaction")

            OpenId4VciServer.CredentialResponse.Plain(response).toHttpResponse().apply {
                status shouldBe HttpStatusCode.OK
                headers[HttpHeaders.ContentType] shouldBe MediaTypes.Application.JSON
                headers[HttpHeaders.CacheControl] shouldBe "no-store"
                joseCompliantSerializer.decodeFromString<CredentialResponseParameters>(body) shouldBe response
            }
        }

        test("encrypted as JWT, not cached") {
            val jwe = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSJ9..aXY.Y2lwaGVydGV4dA.dGFn"

            OpenId4VciServer.CredentialResponse.Encrypted(JweEncrypted.deserialize(jwe).getOrThrow())
                .toHttpResponse().apply {
                    status shouldBe HttpStatusCode.OK
                    headers[HttpHeaders.ContentType] shouldBe MediaTypes.Application.JWT
                    headers[HttpHeaders.CacheControl] shouldBe "no-store"
                    body shouldBe jwe
                }
        }
    }
}

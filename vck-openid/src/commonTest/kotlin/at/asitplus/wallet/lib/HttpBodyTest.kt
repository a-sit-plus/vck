package at.asitplus.wallet.lib

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.ktor.http.*

val HttpBodyTest by matrixSuite {

    test("request with Content-Type in its headers is rejected, as it is set with the body") {
        listOf(HttpHeaders.ContentType, "content-type").forEach { name ->
            shouldThrow<IllegalArgumentException> {
                PreparedHttpRequest(
                    url = "https://example.com",
                    method = HttpMethod.Post,
                    headers = headersOf(name, ContentType.Application.Json.toString()),
                    body = HttpBody(ContentType.Application.Json, "{}"),
                )
            }
        }
    }
}

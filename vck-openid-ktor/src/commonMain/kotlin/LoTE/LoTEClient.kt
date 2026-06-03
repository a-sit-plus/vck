package LoTE

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.etsi.ListOfTrustedEntities
import at.asitplus.etsi.TrustListPayload
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import io.github.aakira.napier.Napier
import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.plugins.DefaultRequest
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.accept
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.serialization.kotlinx.json.json

class LoTEClient(
    /** ktor engine to use to make requests to the trust list service. */
    engine: HttpClientEngine,
    /** Additional configuration for building the HTTP client, e.g. callers may enable logging. */
    httpClientConfig: (HttpClientConfig<*>.() -> Unit)? = null,
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
) {

    val client: HttpClient = HttpClient(engine) {
        followRedirects = false
        install(ContentNegotiation) {
            json(joseCompliantSerializer)
        }
        install(DefaultRequest.Plugin) {
            header(HttpHeaders.ContentType, ContentType.Application.Json)
        }
        httpClientConfig?.let { apply(it) }
    }

    /**
     * Fetches the signed List of Trusted Entities (LoTE)
     * Returns a [KmmResult] wrapping the [ListOfTrustedEntities] on success.
     */
    suspend fun fetchTrustList(url: String): KmmResult<ListOfTrustedEntities> = catching {
        Napier.i("Fetching Trust List from: $url")
        val response = client.get(url) {
            accept(ContentType.Application.Json)
        }

        val responseBody = response.bodyAsText()

        val (jwsCompact, payload) = JwsCompact.parse<TrustListPayload>(responseBody).getOrThrow()

        verifyJwsObject(jwsCompact).getOrThrow()

        Napier.i("Successfully validated Trust List signature from $url")
        payload.loTe
    }
}
package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.dcapi.request.DCAPIWalletRequest
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.AuthorizationResponsePreparationState
import at.asitplus.wallet.lib.openid.OpenId4VpHolder
import io.github.aakira.napier.Napier
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.http.content.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.utils.io.core.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Implements the wallet side of
 * [Self-Issued OpenID Provider v2 - draft 13](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)
 * and
 * [OpenID for Verifiable Presentations - draft 21](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
 */
class OpenId4VpWallet(
    /** ktor engine to make requests to the verifier. */
    engine: HttpClientEngine,
    /** Additional configuration for building the HTTP client, e.g. callers may enable logging. */
    httpClientConfig: (HttpClientConfig<*>.() -> Unit)? = null,
    keyMaterial: KeyMaterial,
    holderAgent: HolderAgent,
    /** Source for random bytes, i.e., nonces for encrypted responses. */
    randomSource: RandomSource = RandomSource.Secure,
) {

    sealed interface AuthenticationResult

    data class AuthenticationSuccess(
        val redirectUri: String? = null,
    ) : AuthenticationResult

    data class AuthenticationForward(
        val authenticationResponseResult: AuthenticationResponseResult.DcApi,
    ) : AuthenticationResult


    private val client: HttpClient = HttpClient(engine) {
        followRedirects = false
        install(ContentNegotiation) {
            json(vckJsonSerializer)
        }
        install(DefaultRequest) {
            header(HttpHeaders.ContentType, ContentType.Application.Json)
        }
        httpClientConfig?.let { apply(it) }
    }

    val openId4VpHolder = OpenId4VpHolder(
        holder = holderAgent,
        keyMaterial = keyMaterial,
        remoteResourceRetriever = { data ->
            withContext(Dispatchers.IO) {
                if (data.method == HttpMethod.Post) {
                    client.submitForm(
                        url = data.url,
                        formParameters = parameters {
                            data.requestObjectParameters?.encodeToParameters()?.forEach { append(it.key, it.value) }
                        }
                    ) {
                        data.headers.forEach {
                            headers[it.key] = it.value
                        }
                    }.bodyAsText()
                } else {
                    client.get(URLBuilder(data.url).apply {
                        data.requestObjectParameters?.encodeToParameters()
                            ?.forEach { parameters.append(it.key, it.value) }
                    }.build()) {
                        data.headers.forEach {
                            headers[it.key] = it.value
                        }
                    }.bodyAsText()
                }
            }
        },
        randomSource = randomSource,
        requestObjectJwsVerifier = { _ -> true }, // unsure about this one?
    )

    /**
     * Sends an error response with the appropriate method.
     * Returns nothing as we don't expect a useful response from the remote verifier.
     */
    suspend fun sendAuthnErrorResponse(
        error: Throwable,
        request: RequestParametersFrom<AuthenticationRequestParameters>,
    ) {
        catchingUnwrapped {
            Napier.i("sendAuthnErrorResponse $error, $request")
            openId4VpHolder.createAuthnErrorResponse(error = error, request = request).getOrThrow().let {
                when (it) {
                    is AuthenticationResponseResult.Post -> postResponse(it)
                    is AuthenticationResponseResult.Redirect -> redirectResponse(it)
                    is AuthenticationResponseResult.DcApi ->
                        Napier.d("Unsupported error response mode")
                }
            }
        }
    }

    suspend fun startAuthorizationResponsePreparation(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
    ): KmmResult<AuthorizationResponsePreparationState> =
        openId4VpHolder.startAuthorizationResponsePreparation(request)

    suspend fun startAuthorizationResponsePreparation(
        input: String,
    ): KmmResult<AuthorizationResponsePreparationState> =
        openId4VpHolder.startAuthorizationResponsePreparation(input)

    suspend fun startAuthorizationResponsePreparation(
        input: DCAPIWalletRequest.OpenId4Vp,
    ): KmmResult<AuthorizationResponsePreparationState> =
        openId4VpHolder.startAuthorizationResponsePreparation(input)

    /**
     * Calls [openId4VpHolder] to finalize the authentication response.
     * In case the result shall be POSTed to the verifier, we call [client] to do that,
     * and return the `redirect_uri` of that POST (which the Wallet may open in a browser).
     * In case the result shall be sent as a redirect to the verifier, we return that URL.
     */
    suspend fun startPresentationReturningUrl(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
    ): KmmResult<AuthenticationSuccess> = catching {
        Napier.i("startPresentation: $request")
        openId4VpHolder.createAuthnResponse(request).getOrThrow().let {
            when (it) {
                is AuthenticationResponseResult.Post -> postResponse(it)
                is AuthenticationResponseResult.Redirect -> redirectResponse(it)
                is AuthenticationResponseResult.DcApi -> throw UnsupportedOperationException("Returning a URL not supported for DC API")
            }
        }
    }

    /**
     * Calls [openId4VpHolder] to finalize the authentication response.
     * In case the result shall be POSTed to the verifier, we call [client] to do that,
     * and return the `redirect_uri` of that POST (which the Wallet may open in a browser).
     * In case the result shall be sent as a redirect to the verifier, we return that URL.
     * In case the result shall be returned via the Digital Credentials API, an [AuthenticationForward]
     * will be returned with the result to be forwarded.
     *
     * Exceptions may be sent to the verifier in [sendAuthnErrorResponse].
     */
    suspend fun finalizeAuthorizationResponse(
        preparationState: AuthorizationResponsePreparationState,
        credentialPresentation: CredentialPresentation? = null,
    ): KmmResult<AuthenticationResult> = catching {
        Napier.i("startPresentation: $preparationState")
        openId4VpHolder.finalizeAuthorizationResponse(
            preparationState = preparationState,
            credentialPresentation = credentialPresentation
        ).getOrElse {
            sendAuthnErrorResponse(it, preparationState.request)
            throw it
        }.let {
            handleResponseResult(it)
        }
    }

    private suspend fun handleResponseResult(
        response: AuthenticationResponseResult,
    ): AuthenticationResult = when (response) {
        is AuthenticationResponseResult.Post -> postResponse(response)
        is AuthenticationResponseResult.Redirect -> redirectResponse(response)
        is AuthenticationResponseResult.DcApi -> AuthenticationForward(response)
    }

    private suspend fun postResponse(it: AuthenticationResponseResult.Post) = run {
        Napier.i("postResponse: $it")
        handlePostResponse(
            client.request {
                url(it.url)
                method = HttpMethod.Post
                setBody(FormDataContentPlain(parameters {
                    it.params.forEach { append(it.key, it.value) }
                }))
            }
        )
    }

    /**
     * Exceptions may be sent to the verifier in [sendAuthnErrorResponse].
     */
    suspend fun getMatchingCredentials(
        preparationState: AuthorizationResponsePreparationState,
    ) = catchingUnwrapped {
        openId4VpHolder.getMatchingCredentials(preparationState).getOrThrow()
    }

    /**
     * Our implementation of ktor's [FormDataContent], but with [contentType] without charset appended,
     * so that some strict mDoc verifiers accept our authn response
     */
    class FormDataContentPlain(
        formData: Parameters,
    ) : OutgoingContent.ByteArrayContent() {
        private val content = formData.formUrlEncode().toByteArray()
        override val contentLength: Long = content.size.toLong()
        override val contentType: ContentType = ContentType.Application.FormUrlEncoded
        override fun bytes(): ByteArray = content
    }


    @Throws(Exception::class)
    private suspend fun handlePostResponse(response: HttpResponse) = run {
        Napier.i("handlePostResponse: response $response")
        when (response.status.value) {
            in 200..399 -> AuthenticationSuccess(response.extractRedirectUri())
            else -> throw Exception("${response.status}: ${response.readRawBytes().decodeToString()}")
        }
    }

    private fun redirectResponse(it: AuthenticationResponseResult.Redirect) = run {
        Napier.i("redirectResponse: ${it.url}")
        AuthenticationSuccess(it.url)
    }
}

@Serializable
data class OpenId4VpSuccess(
    @SerialName("redirect_uri")
    val redirectUri: String,
)

private suspend fun HttpResponse.extractRedirectUri(): String? =
    headers[HttpHeaders.Location]?.let {
        it.ifEmpty { null }
    } ?: catchingUnwrapped { body<OpenId4VpSuccess>() }.getOrNull()?.let {
        it.redirectUri.ifEmpty { null }
    }

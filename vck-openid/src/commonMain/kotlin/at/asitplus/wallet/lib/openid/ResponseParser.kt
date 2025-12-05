package at.asitplus.wallet.lib.openid

import at.asitplus.catchingUnwrapped
import at.asitplus.dcapi.OpenId4VpResponse
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.ResponseParametersFrom
import at.asitplus.signum.indispensable.josef.JweDecrypted
import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.DecryptJwe
import at.asitplus.wallet.lib.jws.DecryptJweFun
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.oidvci.decodeFromPostBody
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import io.ktor.http.*
import kotlin.coroutines.cancellation.CancellationException

/**
 * Parses authentication responses for [OpenId4VpVerifier]
 */
class ResponseParser(
    private val decryptJwe: DecryptJweFun = DecryptJwe(EphemeralKeyWithoutCert()),
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
) {
    /**
     * Parses [at.asitplus.openid.AuthenticationResponseParameters], where [input] is either:
     * - a URL, containing parameters in the fragment, e.g. `https://example.com#id_token=...`
     * - a URL, containing parameters in the query, e.g. `https://example.com?id_token=...`
     * - parameters encoded as a POST body, e.g. `id_token=...&vp_token=...`
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    suspend fun parseAuthnResponse(input: String) = input.parseResponseParameters().extractFromJar()

    /**
     * Parses [at.asitplus.openid.AuthenticationResponseParameters], where [input] is a signed or unsigned DC API
     * response.
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    suspend fun parseAuthnResponse(input: OpenId4VpResponse) =
        ResponseParametersFrom.DcApi.createFromOpenId4VpResponse(input).extractFromJar()

    private fun String.parseResponseParameters() : ResponseParametersFrom = parseUrlSafe(this)
        ?: parsePostBodySafe(this)
        ?: throw IllegalArgumentException("Can't parse input: $this")

    private fun parsePostBodySafe(input: String) =
        catchingUnwrapped { input.parseAsPostBody() }.getOrNull()

    /** Treat input as POST body, parse parameters */
    private fun String.parseAsPostBody() = if (contains("=")) {
        decodeFromPostBody<AuthenticationResponseParameters>()
            .let { ResponseParametersFrom.Post(it) }
    } else null

    private fun parseUrlSafe(input: String) =
        catchingUnwrapped { input.parseAsUrl() }.getOrNull()

    /** Treat input as URL, parse fragment or query */
    private fun String.parseAsUrl() = with(Url(this)) {
        if (encodedFragment.isNotEmpty()) {
            encodedFragment.decodeFromUrlQuery<AuthenticationResponseParameters>()
                .let { ResponseParametersFrom.Uri(this, it) }
        } else {
            encodedQuery.decodeFromUrlQuery<AuthenticationResponseParameters>()
                .let { ResponseParametersFrom.Uri(this, it) }
        }
    }

    /**
     * Extracts [AuthenticationResponseParameters] from [this@extractFromJar] if it is encoded there as
     * [AuthenticationResponseParameters.response], which may be a JWS or JWE.
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    internal suspend fun ResponseParametersFrom.extractFromJar() = parameters.response?.let { encodedResponse ->
        encodedResponse.fromJws()?.let { jws ->
            verifyJwsObject(jws).getOrElse {
                throw IllegalArgumentException("JWS not verified: $encodedResponse", it)
            }
            ResponseParametersFrom.JwsSigned(jws, this, jws.payload, this.clientIdRequired)
        } ?: encodedResponse.fromJwe()?.let { jwe ->
            ResponseParametersFrom.JweDecrypted(jwe, this, jwe.payload, this.clientIdRequired)
        } ?: throw IllegalArgumentException("Got encoded response, but could not deserialize it from $this")
    } ?: this

    private suspend fun String.fromJwe(): JweDecrypted<AuthenticationResponseParameters>? =
        JweEncrypted.deserialize(this).getOrNull()?.let { encrypted ->
            decryptJwe(encrypted).getOrThrow().let { decrypted ->
                JweDecrypted(decrypted.header, decrypted.parseResponseParams())
            }
        }

    private fun JweDecrypted<String>.parseResponseParams(): AuthenticationResponseParameters =
        vckJsonSerializer.decodeFromString<AuthenticationResponseParameters>(payload)

    private fun String.fromJws(): JwsSigned<AuthenticationResponseParameters>? =
        JwsSigned.deserialize(AuthenticationResponseParameters.serializer(), this, vckJsonSerializer).getOrNull()

}
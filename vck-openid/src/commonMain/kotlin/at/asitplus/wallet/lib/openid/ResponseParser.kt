package at.asitplus.wallet.lib.openid

import at.asitplus.catchingUnwrapped
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
import io.github.aakira.napier.Napier
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
    suspend fun parseAuthnResponse(input: String): ResponseParametersFrom {
        val paramsFrom = catchingUnwrapped {
            val url = Url(input)
            if (url.encodedFragment.isNotEmpty()) {
                url.encodedFragment.decodeFromUrlQuery<AuthenticationResponseParameters>().let {
                    ResponseParametersFrom.Uri(url, it)
                }
            } else {
                url.encodedQuery.decodeFromUrlQuery<AuthenticationResponseParameters>().let {
                    ResponseParametersFrom.Uri(url, it)
                }
            }
        }.getOrNull() ?: if (input.contains("=")) {
            input.decodeFromPostBody<AuthenticationResponseParameters>().let {
                ResponseParametersFrom.Post(it)
            }
        } else throw IllegalArgumentException("Can't parse input")
            .also { Napier.w("Could not parse authentication response: $input") }
        return extractAuthnResponse(paramsFrom)
    }

    /**
     * Extracts [AuthenticationResponseParameters] from [input] if it is encoded there as
     * [AuthenticationResponseParameters.response], which may be a JWS or JWE.
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    internal suspend fun extractAuthnResponse(input: ResponseParametersFrom): ResponseParametersFrom =
        input.parameters.response?.let { encodedResponse ->
            encodedResponse.fromJws()?.let { jarm ->
                if (!verifyJwsObject(jarm)) {
                    Napier.w("JWS of response not verified: $encodedResponse")
                    throw IllegalArgumentException("JWS not verified")
                }
                ResponseParametersFrom.JwsSigned(jarm, input, jarm.payload)
            } ?: encodedResponse.fromJwe()?.let { jarm ->
                ResponseParametersFrom.JweDecrypted(jarm, input, jarm.payload)
            } ?: encodedResponse.fromJweString()?.let { jarm ->
                val nested = jarm.payload.fromJws()
                    ?: throw IllegalArgumentException("JWS inside JWE not verified")
                if (!verifyJwsObject(nested)) {
                    Napier.w("JWS inside JWE of response not verified: $encodedResponse")
                    throw IllegalArgumentException("JWS inside JWE not verified")
                }
                ResponseParametersFrom.JwsSigned(
                    nested,
                    ResponseParametersFrom.JweForJws(jarm, input, nested.payload),
                    nested.payload
                )
            } ?: throw IllegalArgumentException("Got encoded response, but could not deserialize it from $input")
        } ?: input

    private suspend fun String.fromJwe(): JweDecrypted<AuthenticationResponseParameters>? =
        JweEncrypted.deserialize(this).getOrNull()?.let {
            decryptJwe(it).getOrNull()?.let {
                JweDecrypted(
                    it.header,
                    vckJsonSerializer.decodeFromString<AuthenticationResponseParameters>(it.payload)
                )
            }
        }

    private suspend fun String.fromJweString(): JweDecrypted<String>? =
        JweEncrypted.deserialize(this).getOrNull()?.let {
            decryptJwe(it).getOrNull()
        }

    private fun String.fromJws(): JwsSigned<AuthenticationResponseParameters>? =
        JwsSigned.Companion.deserialize(
            AuthenticationResponseParameters.Companion.serializer(),
            this,
            vckJsonSerializer
        ).getOrNull()

}
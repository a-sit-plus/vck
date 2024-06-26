package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import io.github.aakira.napier.Napier
import io.ktor.http.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

@Serializable
sealed class AuthenticationRequestParametersFrom<T>(val source: T, val parameters: AuthenticationRequestParameters) {

    class JwsSigned(
        jwsSigned: at.asitplus.crypto.datatypes.jws.JwsSigned,
        parameters: AuthenticationRequestParameters,
    ) : AuthenticationRequestParametersFrom<at.asitplus.crypto.datatypes.jws.JwsSigned>(jwsSigned, parameters)

    class Uri(url: Url, parameters: AuthenticationRequestParameters) :
        AuthenticationRequestParametersFrom<Url>(url, parameters)

    class Json(jsonString: String, parameters: AuthenticationRequestParameters) :
        AuthenticationRequestParametersFrom<String>(jsonString, parameters)

    override fun equals(other: Any?): Boolean =
        other is AuthenticationRequestParametersFrom<*> && this.source == other.source && this.parameters == other.parameters

    override fun hashCode(): Int {
        var result = source?.hashCode() ?: 0
        result = 31 * result + parameters.hashCode()
        return result
    }

    fun serialize(): String {
        val sourceEncoded = when(source) {
            is at.asitplus.crypto.datatypes.jws.JwsSigned -> source.serialize()
            else -> source.toString()
        }
        return jsonSerializer.encodeToString(
            mapOf("source" to sourceEncoded, "parameter" to parameters.serialize())
        )
    }

    override fun toString(): String {
        return "AuthenticationRequestParametersFrom(source=$source, parameters=${parameters})"
    }

    companion object {

        fun deserialize(it: String): KmmResult<AuthenticationRequestParametersFrom<*>> {
            return kotlin.runCatching {
                val inputMap = jsonSerializer.decodeFromString<Map<String, String>>(it)
                val source = kotlin.run {
                    inputMap["source"]?.let {
                        when {
                            at.asitplus.crypto.datatypes.jws.JwsSigned.parse(it).isSuccess -> at.asitplus.crypto.datatypes.jws.JwsSigned.parse(
                                it
                            ).getOrNull()!!

                            isValidUrl(it) -> Url(it)

                            kotlin.runCatching { jsonSerializer.parseToJsonElement(it) }.isSuccess -> it

                            else -> throw Exception("Cannot deserialize AuthenticationRequestParametersFrom<*> from $it")
                        }
                    } ?: throw Exception("Cannot deserialize AuthenticationRequestParametersFrom<*> from $it")
                }
                val param =
                    inputMap["parameter"]?.let { jsonSerializer.decodeFromString<AuthenticationRequestParameters>(it) }
                        ?: throw Exception("Cannot deserialize AuthenticationRequestParametersFrom<*> from $it")

                when (source) {
                    is Url -> Uri(source, param)
                    is at.asitplus.crypto.datatypes.jws.JwsSigned -> JwsSigned(source, param)
                    is String -> Json(source, param)
                    else -> throw Exception("Unknown AuthenticationRequestParametersFrom<*> from $it")
                }.also { Napier.d { it.toString() } }
            }.wrap()
        }
    }
}

private fun isValidUrl(url: String): Boolean {
    val urlRegex = """^\S+://[^\s/$.?#].\S*$""".toRegex()
    return urlRegex.matches(url)
}
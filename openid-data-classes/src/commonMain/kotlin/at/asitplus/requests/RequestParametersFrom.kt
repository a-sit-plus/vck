package at.asitplus.requests

import at.asitplus.openid.JwsSignedSerializer
import at.asitplus.openid.UrlSerializer
import at.asitplus.requests.RequestParametersFrom.Json
import at.asitplus.requests.RequestParametersFrom.JwsSigned
import io.ktor.http.Url
import kotlinx.serialization.Serializable

@Serializable(with = RequestParametersFromSerializer::class)
sealed class RequestParametersFrom<S : RequestParameters> {

    abstract val parameters: S

    @Serializable
    data class JwsSigned<T : RequestParameters>(
        @Serializable(JwsSignedSerializer::class)
        val jwsSigned: at.asitplus.signum.indispensable.josef.JwsSigned<T>,
        override val parameters: T,
        val dcApiRequest: DcApiRequest? = null
    ) : RequestParametersFrom<T>() {
        override fun toString(): String {
            return "JwsSigned(jwsSigned=${jwsSigned.serialize()}, parameters=$parameters)"
        }
    }

    @Serializable
    data class Uri<T : RequestParameters>(
        @Serializable(UrlSerializer::class)
        val url: Url,
        override val parameters: T,
    ) : RequestParametersFrom<T>() {
        override fun toString(): String {
            return "Uri(url=$url, parameters=$parameters)"
        }
    }

    @Serializable
    data class Json<T : RequestParameters>(
        val jsonString: String,
        override val parameters: T,
        val dcApiRequest: DcApiRequest? = null
    ) : RequestParametersFrom<T>() {
        override fun toString(): String {
            return "Json(jsonString='$jsonString', parameters=$parameters)"
        }
    }
}

fun RequestParametersFrom<*>.extractDcApiRequest() = (this as? Json?)?.dcApiRequest
    ?: (this as? JwsSigned?)?.dcApiRequest
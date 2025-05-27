package at.asitplus.openid

import at.asitplus.dcapi.request.DCAPIRequest
import io.ktor.http.*
import kotlinx.serialization.Serializable

@Serializable(with = RequestParametersFromSerializer::class)
sealed class RequestParametersFrom<S : RequestParameters> {

    abstract val parameters: S

    @Serializable
    data class JwsSigned<T : RequestParameters>(
        @Serializable(JwsSignedSerializer::class)
        val jwsSigned: at.asitplus.signum.indispensable.josef.JwsSigned<T>,
        override val parameters: T,
        val dcApiRequest: DCAPIRequest? = null
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
        val dcApiRequest: DCAPIRequest? = null
    ) : RequestParametersFrom<T>() {
        override fun toString(): String {
            return "Json(jsonString='$jsonString', parameters=$parameters)"
        }
    }
}



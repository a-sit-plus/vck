package at.asitplus.openid

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
    ) : RequestParametersFrom<T>()

    @Serializable
    data class Uri<T : RequestParameters>(
        @Serializable(UrlSerializer::class)
        val url: Url,
        override val parameters: T,
    ) : RequestParametersFrom<T>()

    @Serializable
    data class Json<T : RequestParameters>(
        val jsonString: String,
        override val parameters: T,
    ) : RequestParametersFrom<T>()
}



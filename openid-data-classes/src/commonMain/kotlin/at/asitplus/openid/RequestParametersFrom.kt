package at.asitplus.openid

import at.asitplus.dcapi.request.DCAPIWalletRequest
import at.asitplus.signum.indispensable.josef.JWS
import at.asitplus.signum.indispensable.josef.JwsCompactStringSerializer
import at.asitplus.signum.indispensable.josef.JwsGeneral
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable(with = RequestParametersFromSerializer::class)
sealed class RequestParametersFrom<S : RequestParameters> {

    abstract val parameters: S

    /**
     * Common ancestor for request parameters that are represented with a JWS signature
     * (e.g., classic OpenID requests or DC-API signed requests).
     */
    @Serializable
    sealed class RequestParametersSigned<T : RequestParameters> : RequestParametersFrom<T>() {
        abstract val jws: JWS
    }

    @Serializable
    @SerialName(SerialNames.TYPE_JWS_COMPACT)
    data class JwsCompact<T : RequestParameters>(
        @Serializable(JwsCompactStringSerializer::class)
        @SerialName(SerialNames.JWS_COMPACT)
        override val jws: at.asitplus.signum.indispensable.josef.JwsCompact,
        @SerialName(SerialNames.PARAMETERS)
        override val parameters: T,
        @SerialName(SerialNames.VERIFIED)
        val verified: Boolean,
        @SerialName(SerialNames.PARENT)
        val parent: Url?,
    ) : RequestParametersSigned<T>() {
        override fun toString(): String {
            return "jws(parent='$parent', jws=$jws, parameters=$parameters, verified=$verified)"
        }
    }

    @Serializable
    @SerialName(SerialNames.TYPE_DCAPI_MULTISIGNED)
    data class DcApiMultiSigned<T : RequestParameters>(
        @SerialName(SerialNames.DC_API_REQUEST)
        val dcApiRequest: DCAPIWalletRequest.OpenId4VpMultiSigned,
        @SerialName(SerialNames.PARAMETERS)
        override val parameters: T,
        @SerialName(SerialNames.JWS_GENERAL)
        override val jws: JwsGeneral,
    ) : RequestParametersSigned<T>() {
        override fun toString(): String {
            return "DcApiSigned(dcApiRequest=$dcApiRequest, parameters=$parameters, jws=$jws)"
        }
    }

    @Serializable
    @SerialName(SerialNames.TYPE_DCAPI_SIGNED)
    data class DcApiSigned<T : RequestParameters>(
        @SerialName(SerialNames.DC_API_REQUEST)
        val dcApiRequest: DCAPIWalletRequest.OpenId4VpSigned,
        @SerialName(SerialNames.PARAMETERS)
        override val parameters: T,
        @Serializable(JwsCompactStringSerializer::class)
        @SerialName(SerialNames.JWS_COMPACT)
        override val jws: at.asitplus.signum.indispensable.josef.JwsCompact,
    ) : RequestParametersSigned<T>() {
        override fun toString(): String {
            return "DcApiSigned(dcApiRequest=$dcApiRequest, parameters=$parameters, jws=$jws)"
        }
    }

    @Serializable
    @SerialName(SerialNames.TYPE_DCAPI_UNSIGNED)
    data class DcApiUnsigned<T : RequestParameters>(
        @SerialName(SerialNames.DC_API_REQUEST)
        val dcApiRequest: DCAPIWalletRequest.OpenId4VpUnsigned,
        @SerialName(SerialNames.PARAMETERS)
        override val parameters: T,
        @SerialName(SerialNames.JSON_STRING)
        val jsonString: String,
    ) : RequestParametersFrom<T>() {
        override fun toString(): String {
            return "DcApiUnsigned(dcApiRequest=$dcApiRequest, parameters=$parameters, jsonString='$jsonString')"
        }
    }

    @Serializable
    @SerialName(SerialNames.TYPE_URI)
    data class Uri<T : RequestParameters>(
        @Serializable(UrlSerializer::class)
        val url: Url,
        @SerialName(SerialNames.PARAMETERS)
        override val parameters: T,
    ) : RequestParametersFrom<T>() {
        override fun toString(): String {
            return "Uri(url=$url, parameters=$parameters)"
        }
    }

    @Serializable
    @SerialName(SerialNames.TYPE_JSON)
    data class Json<T : RequestParameters>(
        @SerialName(SerialNames.JSON_STRING)
        val jsonString: String,
        @SerialName(SerialNames.PARAMETERS)
        override val parameters: T,
        @SerialName(SerialNames.PARENT)
        val parent: Url?,
    ) : RequestParametersFrom<T>() {
        override fun toString(): String {
            return "Json(parent='$parent', jsonString='$jsonString', parameters=$parameters)"
        }
    }

    object SerialNames {
        const val TYPE_JWS_COMPACT = "JwsCompact"
        const val TYPE_JSON = "Json"
        const val TYPE_DCAPI_UNSIGNED = "DcApiUnsigned"
        const val TYPE_DCAPI_SIGNED = "DcApiSigned"
        const val TYPE_DCAPI_MULTISIGNED = "DcApiMultiSigned"
        const val TYPE_URI = "Uri"

        const val JWS_COMPACT = "jwsCompact"
        const val JWS_GENERAL = "jwsGeneral"
        const val JSON_STRING = "jsonString"
        const val URL = "url"
        const val PARENT = "parent"
        const val PARAMETERS = "parameters"
        const val DC_API_REQUEST = "dcApiRequest"
        const val VERIFIED = "verified"
    }

}
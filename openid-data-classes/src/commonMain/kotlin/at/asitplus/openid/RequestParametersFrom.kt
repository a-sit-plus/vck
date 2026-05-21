package at.asitplus.openid

import at.asitplus.dcapi.request.ExchangeProtocolIdentifier
import at.asitplus.dcapi.request.IsoMdocRequest
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.JWS
import at.asitplus.signum.indispensable.josef.JwsCompactStringSerializer
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JwsGeneral
import at.asitplus.signum.indispensable.josef.JwsGeneralTyped
import at.asitplus.signum.indispensable.josef.JwsTyped
import io.ktor.http.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonClassDiscriminator

@Serializable(with = RequestParametersFromSerializer::class)
sealed class RequestParametersFrom<S : RequestParameters> {

    abstract val parameters: S

    /**
     * Common ancestor for request parameters that are represented with a JWS signature
     * (e.g., classic OpenID requests or DC-API signed requests).
     */
    sealed class RequestParametersSigned<T : RequestParameters> : RequestParametersFrom<T>() {
        abstract val jwsTyped: JwsTyped<*, T>
        abstract val verified: Boolean
    }

    /**
     * Common ancestor for request parameters that are DC-API subtypes
     */
    @JsonClassDiscriminator("protocol")
    sealed interface DcApiRequest {
        @SerialName("credentialIds")
        val credentialIds: Collection<String>

        @SerialName("callingPackageName")
        val callingPackageName: String

        @SerialName("callingOrigin")
        val callingOrigin: String

        val protocol: ExchangeProtocolIdentifier
    }

    @Serializable
    @SerialName(SerialNames.TYPE_JWS)
    data class Jws<T : RequestParameters>(
        @SerialName(SerialNames.JWS)
        val jws: JWS,
        @SerialName(SerialNames.PARAMETERS)
        override val parameters: T,
        @SerialName(SerialNames.VERIFIED)
        override val verified: Boolean,
        @SerialName(SerialNames.PARENT)
        val parent: Url? = null,
    ) : RequestParametersSigned<T>() {
        override val jwsTyped get() = JwsTyped(jws, parameters)
    }

    @Serializable
    @SerialName(SerialNames.TYPE_DCAPI_MULTISIGNED)
    data class OpenId4VpMultiSigned(
        @Serializable(with = JwsGeneralAuthParamSerializer::class)
        @SerialName(SerialNames.JWS)
        override val jwsTyped: JwsGeneralTyped<AuthenticationRequestParameters>,
        @SerialName(SerialNames.VERIFIED)
        override val verified: Boolean,
        @SerialName("credentialIds")
        override val credentialIds: Collection<String>,
        @SerialName("callingPackageName")
        override val callingPackageName: String,
        @SerialName("callingOrigin")
        override val callingOrigin: String
    ) : RequestParametersSigned<AuthenticationRequestParameters>(), DcApiRequest {

        @SerialName(SerialNames.PARAMETERS)
        override val parameters: AuthenticationRequestParameters = jwsTyped.payload

        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OpenId4VpV1Multisigned

        object JwsGeneralAuthParamSerializer :
            KSerializer<JwsGeneralTyped<AuthenticationRequestParameters>> by JwsTypedSerializerTemplate(
                JwsGeneral.serializer(),
                AuthenticationRequestParameters.serializer()
            )
    }

    @Serializable
    @SerialName(SerialNames.TYPE_DCAPI_SIGNED)
    data class OpenId4VpSigned(
        @Serializable(JwsCompactAuthParamSerializer::class)
        @SerialName(SerialNames.JWS)
        override val jwsTyped: JwsCompactTyped<AuthenticationRequestParameters>,
        @SerialName(SerialNames.VERIFIED)
        override val verified: Boolean,
        @SerialName("credentialIds")
        override val credentialIds: Collection<String>,
        @SerialName("callingPackageName")
        override val callingPackageName: String,
        @SerialName("callingOrigin")
        override val callingOrigin: String
    ) : RequestParametersSigned<AuthenticationRequestParameters>(), DcApiRequest {

        @SerialName(SerialNames.PARAMETERS)
        override val parameters: AuthenticationRequestParameters = jwsTyped.payload

        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OpenId4VpV1Signed

        object JwsCompactAuthParamSerializer :
            KSerializer<JwsCompactTyped<AuthenticationRequestParameters>> by JwsTypedSerializerTemplate(
                JwsCompactStringSerializer,
                AuthenticationRequestParameters.serializer()
            )

    }

    @Serializable
    @SerialName(SerialNames.TYPE_DCAPI_UNSIGNED)
    data class OpenId4VpUnsigned(
        @SerialName(SerialNames.PARAMETERS)
        override val parameters: AuthenticationRequestParameters,
        @SerialName(SerialNames.JSON_STRING)
        val jsonString: String,
        @SerialName("credentialIds")
        override val credentialIds: Collection<String>,
        @SerialName("callingPackageName")
        override val callingPackageName: String,
        @SerialName("callingOrigin")
        override val callingOrigin: String
    ) : DcApiRequest, RequestParametersFrom<AuthenticationRequestParameters>() {

        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OpenId4VpV1Unsigned

    }

    @Serializable
    @SerialName(SerialNames.TYPE_DCAPI_ISO_MDOC)
    data class IsoMdoc(
        override val parameters: IsoMdocRequestWrapper,
        @SerialName(SerialNames.JSON_STRING)
        val jsonString: String,
        @SerialName("credentialIds")
        override val credentialIds: Collection<String>,
        @SerialName("callingPackageName")
        override val callingPackageName: String,
        @SerialName("callingOrigin")
        override val callingOrigin: String
    ) : DcApiRequest, RequestParametersFrom<IsoMdoc.IsoMdocRequestWrapper>() {

        @Serializable(with = IsoMdocRequestWrapper.Serializer::class)
        data class IsoMdocRequestWrapper(
            val isoMdocRequest: IsoMdocRequest
        ) : RequestParameters() {
            object Serializer :
                KSerializer<IsoMdocRequestWrapper> by TransformingSerializerTemplate(
                    parent = IsoMdocRequest.serializer(),
                    encodeAs = { it.isoMdocRequest },
                    decodeAs = { IsoMdocRequestWrapper(it) }
                )
        }

        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.IsoMdocAnnexC

    }


    @Serializable
    @SerialName(SerialNames.TYPE_URI)
    data class Uri<T : RequestParameters>(
        @Serializable(UrlSerializer::class)
        val url: Url,
        @SerialName(SerialNames.PARAMETERS)
        override val parameters: T,
    ) : RequestParametersFrom<T>()

    @Serializable
    @SerialName(SerialNames.TYPE_JSON)
    data class Json<T : RequestParameters>(
        @SerialName(SerialNames.JSON_STRING)
        val jsonString: String,
        @SerialName(SerialNames.PARAMETERS)
        override val parameters: T,
        @SerialName(SerialNames.PARENT)
        val parent: Url? = null,
    ) : RequestParametersFrom<T>()

    object SerialNames {
        const val TYPE_JWS = "Jws"
        const val TYPE_JSON = "Json"
        const val TYPE_DCAPI_UNSIGNED = "DcApiUnsigned"
        const val TYPE_DCAPI_SIGNED = "DcApiSigned"
        const val TYPE_DCAPI_MULTISIGNED = "DcApiMultiSigned"
        const val TYPE_DCAPI_ISO_MDOC = "IsoMdoc"
        const val TYPE_URI = "Uri"

        const val JWS = "jws"
        const val JSON_STRING = "jsonString"
        const val URL = "url"
        const val PARENT = "parent"
        const val PARAMETERS = "parameters"
        const val DC_API_REQUEST = "dcApiRequest"
        const val VERIFIED = "verified"
    }

}

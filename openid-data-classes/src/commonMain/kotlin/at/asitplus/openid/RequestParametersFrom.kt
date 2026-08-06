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
import kotlin.jvm.JvmOverloads

/**
 * This class tracks Requests, their contents and their origin with relevant parameters.
 *
 * Used for data management. Does not follow any standard in particular
 */
@Serializable(with = RequestParametersFromSerializer::class)
sealed class RequestParametersFrom<S : RequestParameters> {

    abstract val parameters: S

    /**
     * Common ancestor for request parameters that are represented with a JWS signature
     * (e.g., classic OpenID requests or DC-API signed requests).
     */
    sealed class RequestParametersSigned<T : RequestParameters> : RequestParametersFrom<T>() {
        abstract val jwsTyped: JwsTyped<*, T>
    }

    /**
     * Common ancestor for request parameters that are DC-API subtypes
     */
    @Serializable
    @JsonClassDiscriminator("protocol")
    sealed interface DcApiRequest {
        @SerialName(SerialNames.CREDENTIAL_IDS)
        val credentialIds: Collection<String>?

        @SerialName(SerialNames.CALLING_PACKAGE_NAME)
        val callingPackageName: String?

        @SerialName(SerialNames.CALLING_ORIGIN)
        val callingOrigin: String

        val protocol: ExchangeProtocolIdentifier

        object SerialNames {
            const val CREDENTIAL_IDS = "credentialIds"
            const val CALLING_PACKAGE_NAME = "callingPackageName"
            const val CALLING_ORIGIN = "callingOrigin"
        }
    }

    @Serializable
    @SerialName(SerialNames.TYPE_JWS)
    data class Jws<T : RequestParameters> @JvmOverloads constructor(
        @SerialName(SerialNames.JWS)
        val jws: JWS,
        @SerialName(SerialNames.PARAMETERS)
        override val parameters: T,
        @SerialName(SerialNames.PARENT)
        val parent: Url? = null,
    ) : RequestParametersSigned<T>() {
        override val jwsTyped get() = JwsTyped(jws, parameters)
    }

    @Serializable
    @SerialName(SerialNames.TYPE_DCAPI_MULTISIGNED)
    data class OpenId4VpDcApiMultiSigned @JvmOverloads constructor(
        @Serializable(with = JwsGeneralAuthParamSerializer::class)
        @SerialName(SerialNames.JWS)
        override val jwsTyped: JwsGeneralTyped<AuthenticationRequestParameters>,
        @SerialName(DcApiRequest.SerialNames.CREDENTIAL_IDS)
        override val credentialIds: Collection<String>,
        @SerialName(DcApiRequest.SerialNames.CALLING_PACKAGE_NAME)
        override val callingPackageName: String,
        @SerialName(DcApiRequest.SerialNames.CALLING_ORIGIN)
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
    data class OpenId4VpDcApiSigned(
        @Serializable(JwsCompactAuthParamSerializer::class)
        @SerialName(SerialNames.JWS)
        override val jwsTyped: JwsCompactTyped<AuthenticationRequestParameters>,
        @SerialName(DcApiRequest.SerialNames.CREDENTIAL_IDS)
        override val credentialIds: Collection<String>,
        @SerialName(DcApiRequest.SerialNames.CALLING_PACKAGE_NAME)
        override val callingPackageName: String,
        @SerialName(DcApiRequest.SerialNames.CALLING_ORIGIN)
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
    data class OpenId4VpDcApiUnsigned(
        @SerialName(SerialNames.PARAMETERS)
        override val parameters: AuthenticationRequestParameters,
        @SerialName(SerialNames.JSON_STRING)
        val jsonString: String,
        @SerialName(DcApiRequest.SerialNames.CREDENTIAL_IDS)
        override val credentialIds: Collection<String>,
        @SerialName(DcApiRequest.SerialNames.CALLING_PACKAGE_NAME)
        override val callingPackageName: String,
        @SerialName(DcApiRequest.SerialNames.CALLING_ORIGIN)
        override val callingOrigin: String
    ) : DcApiRequest, RequestParametersFrom<AuthenticationRequestParameters>() {

        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OpenId4VpV1Unsigned

    }

    @Serializable
    @SerialName(SerialNames.TYPE_DCAPI_ISO_MDOC)
    data class IsoMdocDcApi @JvmOverloads constructor(
        override val parameters: IsoMdocRequestWrapper,
        @SerialName(SerialNames.JSON_STRING)
        val jsonString: String,
        @SerialName(DcApiRequest.SerialNames.CREDENTIAL_IDS)
        override val credentialIds: Collection<String>? = null,
        @SerialName(DcApiRequest.SerialNames.CALLING_PACKAGE_NAME)
        override val callingPackageName: String? = null,
        @SerialName(DcApiRequest.SerialNames.CALLING_ORIGIN)
        override val callingOrigin: String
    ) : DcApiRequest, RequestParametersFrom<IsoMdocDcApi.IsoMdocRequestWrapper>() {

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
    data class Json<T : RequestParameters> @JvmOverloads constructor(
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
        const val TYPE_DCAPI_UNSIGNED = ExchangeProtocolIdentifier.OPENID4VP_V1_UNSIGNED
        const val TYPE_DCAPI_SIGNED = ExchangeProtocolIdentifier.OPENID4VP_V1_SIGNED
        const val TYPE_DCAPI_MULTISIGNED = ExchangeProtocolIdentifier.OPENID4VP_V1_MULTISIGNED
        const val TYPE_DCAPI_ISO_MDOC = ExchangeProtocolIdentifier.ORG_ISO_MDOC
        const val TYPE_URI = "Uri"

        const val JWS = "jws"
        const val JSON_STRING = "jsonString"
        const val URL = "url"
        const val PARENT = "parent"
        const val PARAMETERS = "parameters"
    }

}

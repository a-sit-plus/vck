package at.asitplus.dcapi.request

import at.asitplus.openid.RequestParameters
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonClassDiscriminator

/**
 * Abstract base class for requests received by the wallet via the Digital Credentials API.
 */
@Serializable
@JsonClassDiscriminator("protocol")
sealed interface DCAPIWalletRequest {
    val protocol: ExchangeProtocolIdentifier
    /** The credential ID of the credential the user has chosen in the UI provided by the system.
    Not available on iOS. */
    val credentialId: String?
    /** The package name of the calling (browser) application providing the calling origin. Not available on iOS. */
    val callingPackageName: String?
    val callingOrigin: String

    @Serializable
    data class IsoMdoc(
        @SerialName("isoMdocRequest")
        val isoMdocRequest: IsoMdocRequest,
        @SerialName("credentialId")
        override val credentialId: String? = null,
        @SerialName("callingPackageName")
        override val callingPackageName: String? = null,
        @SerialName("callingOrigin")
        override val callingOrigin: String,
    ) : DCAPIWalletRequest {
        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.ISO_MDOC_ANNEX_C
    }


    sealed class OpenId4Vp {
        abstract val protocol: ExchangeProtocolIdentifier
        abstract val request: RequestParameters
    }

    @Serializable
    data class OpenId4VpSigned(
        @SerialName("request")
        override val request: RequestParameters,
        @SerialName("credentialId")
        override val credentialId: String,
        @SerialName("callingPackageName")
        override val callingPackageName: String,
        @SerialName("callingOrigin")
        override val callingOrigin: String,
    ) : DCAPIWalletRequest, OpenId4Vp() {
        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OPENID4VP_V1_SIGNED
    }


    @Serializable
    data class OpenId4VpUnsigned(
        @SerialName("request")
        override val request: RequestParameters,
        @SerialName("credentialId")
        override val credentialId: String,
        @SerialName("callingPackageName")
        override val callingPackageName: String,
        @SerialName("callingOrigin")
        override val callingOrigin: String,
    ) : DCAPIWalletRequest, OpenId4Vp() {
        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OPENID4VP_V1_UNSIGNED
    }

}

@Deprecated(
    "Replaced with DCAPIWalletRequest.OpenId4VpUnsigned / DCAPIWalletRequest.OpenId4VpSigned depending on your protocol variable",
    level = DeprecationLevel.ERROR
)
class Oid4vpDCAPIRequest

@Deprecated(
    "Replaced with DCAPIWalletRequest",
    replaceWith = ReplaceWith("at.asitplus.dcapi.request.DCAPIWalletRequest"),
    level = DeprecationLevel.ERROR
)
class DCAPIRequest
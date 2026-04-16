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

    /** The credential IDs of the credentials the user has chosen in the UI provided by the system.
    Not available on iOS. */
    val credentialIds: Collection<String>?

    /** The package name of the calling (browser) application providing the calling origin. Not available on iOS. */
    val callingPackageName: String?
    val callingOrigin: String

    @Serializable
    data class IsoMdoc(
        @SerialName("isoMdocRequest")
        val isoMdocRequest: IsoMdocRequest,
        @SerialName("credentialIds")
        override val credentialIds: Collection<String>? = null,
        @SerialName("callingPackageName")
        override val callingPackageName: String? = null,
        @SerialName("callingOrigin")
        override val callingOrigin: String,
    ) : DCAPIWalletRequest {
        @Deprecated(
            "Renamed to credentialIds to support multiple selected credentials",
            replaceWith = ReplaceWith(
                "IsoMdoc(isoMdocRequest = isoMdocRequest, credentialIds = credentialId?.let { listOf(it) }, callingPackageName = callingPackageName, callingOrigin = callingOrigin)"
            )
        )
        constructor(
            isoMdocRequest: IsoMdocRequest,
            credentialId: String? = null,
            callingPackageName: String? = null,
            callingOrigin: String,
        ) : this(
            isoMdocRequest = isoMdocRequest,
            credentialIds = credentialId?.let(::listOf),
            callingPackageName = callingPackageName,
            callingOrigin = callingOrigin,
        )

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
        @SerialName("credentialIds")
        override val credentialIds: Collection<String>,
        @SerialName("callingPackageName")
        override val callingPackageName: String,
        @SerialName("callingOrigin")
        override val callingOrigin: String,
    ) : DCAPIWalletRequest, OpenId4Vp() {
        @Deprecated(
            "Renamed to credentialIds to support multiple selected credentials",
            replaceWith = ReplaceWith(
                "OpenId4VpSigned(request = request, credentialIds = listOf(credentialId), callingPackageName = callingPackageName, callingOrigin = callingOrigin)"
            )
        )
        constructor(
            request: RequestParameters,
            credentialId: String,
            callingPackageName: String,
            callingOrigin: String,
        ) : this(
            request = request,
            credentialIds = listOf(credentialId),
            callingPackageName = callingPackageName,
            callingOrigin = callingOrigin,
        )

        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OPENID4VP_V1_SIGNED
    }


    @Serializable
    data class OpenId4VpUnsigned(
        @SerialName("request")
        override val request: RequestParameters,
        @SerialName("credentialIds")
        override val credentialIds: Collection<String>,
        @SerialName("callingPackageName")
        override val callingPackageName: String,
        @SerialName("callingOrigin")
        override val callingOrigin: String,
    ) : DCAPIWalletRequest, OpenId4Vp() {
        @Deprecated(
            "Renamed to credentialIds to support multiple selected credentials",
            replaceWith = ReplaceWith(
                "OpenId4VpUnsigned(request = request, credentialIds = listOf(credentialId), callingPackageName = callingPackageName, callingOrigin = callingOrigin)"
            )
        )
        constructor(
            request: RequestParameters,
            credentialId: String,
            callingPackageName: String,
            callingOrigin: String,
        ) : this(
            request = request,
            credentialIds = listOf(credentialId),
            callingPackageName = callingPackageName,
            callingOrigin = callingOrigin,
        )

        override val protocol: ExchangeProtocolIdentifier
            get() = ExchangeProtocolIdentifier.OPENID4VP_V1_UNSIGNED

    }

}

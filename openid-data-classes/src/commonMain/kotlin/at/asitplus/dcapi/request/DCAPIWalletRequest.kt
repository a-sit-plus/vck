package at.asitplus.dcapi.request

import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.EncryptionInfo
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Abstract base class for requests received by the wallet via the Digital Credentials API.
 */
@Serializable
sealed interface DCAPIWalletRequest {
    @SerialName("credentialId")
    val credentialId: String
    @SerialName("callingPackageName")
    val callingPackageName: String
    @SerialName("callingOrigin")
    val callingOrigin: String

    @Serializable
    data class IsoMdoc(
        @SerialName("deviceRequest")
        override val deviceRequest: DeviceRequest,
        @SerialName("encryptionInfo")
        override val encryptionInfo: EncryptionInfo,
        @SerialName("credentialId")
        override val credentialId: String,
        @SerialName("callingPackageName")
        override val callingPackageName: String,
        @SerialName("callingOrigin")
        override val callingOrigin: String
    ) : DCAPIWalletRequest, IsoMdocRequestInterface

    @Serializable
    data class Oid4Vp(
        /** Format `openid4vp-v<version>-<request-type>`, see [ExchangeProtocolIdentifier]. */
        @SerialName("protocol")
        val protocol: ExchangeProtocolIdentifier,
        @SerialName("request")
        val request: String,
        @SerialName("credentialId")
        override val credentialId: String,
        @SerialName("callingPackageName")
        override val callingPackageName: String,
        @SerialName("callingOrigin")
        override val callingOrigin: String,
    ) : DCAPIWalletRequest
}

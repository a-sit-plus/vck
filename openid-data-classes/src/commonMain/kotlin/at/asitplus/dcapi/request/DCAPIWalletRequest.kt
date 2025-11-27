package at.asitplus.dcapi.request

import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.EncryptionInfo
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Abstract base class for requests received by the wallet via the Digital Credentials API.
 */
@Serializable
sealed class DCAPIWalletRequest {
    @SerialName("credentialId")
    abstract val credentialId: String
    @SerialName("callingPackageName")
    abstract val callingPackageName: String
    @SerialName("callingOrigin")
    abstract val callingOrigin: String

    @Serializable
    data class IsoMdoc(
        @SerialName("deviceRequest")
        val deviceRequest: DeviceRequest,
        @SerialName("encryptionInfo")
        val encryptionInfo: EncryptionInfo,
        @SerialName("credentialId")
        override val credentialId: String,
        @SerialName("callingPackageName")
        override val callingPackageName: String,
        @SerialName("callingOrigin")
        override val callingOrigin: String
    ) : DCAPIWalletRequest()

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
    ) : DCAPIWalletRequest()
}

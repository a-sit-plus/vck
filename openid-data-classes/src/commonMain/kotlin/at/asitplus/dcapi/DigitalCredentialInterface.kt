package at.asitplus.dcapi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonClassDiscriminator

@Serializable
@JsonClassDiscriminator("protocol")
sealed class DigitalCredentialInterface(
//    /** `org-iso-mdoc`. */
//    @SerialName("protocol")
//    val protocol: ExchangeProtocolIdentifier,
)

@Serializable
@SerialName("org-iso-mdoc")
data class IsoMdocResponse(
    @SerialName("data")
    val data: DCAPIResponse,
) : DigitalCredentialInterface()

@Serializable
@SerialName("oid4vp-v1-signed")
data class Oid4VpResponseSigned(
    @SerialName("data")
    val data: Oid4vpDCAPIResponse,
) : DigitalCredentialInterface()

@Serializable
@SerialName("oid4vp-v1-unsigned")
data class Oid4VpResponseUnsigned(
    @SerialName("data")
    val data: Oid4vpDCAPIResponse,
) : DigitalCredentialInterface()
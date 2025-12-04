package at.asitplus.dcapi

import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.ResponseParametersFrom
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonClassDiscriminator

@Serializable
@JsonClassDiscriminator("protocol")
sealed class DigitalCredentialInterface(
//    /** `org-iso-mdoc`. */
//    @SerialName("protocol")
//    val protocol: ExchangeProtocolIdentifier,

) {
    abstract val origin: String
}

@Serializable
@SerialName("org-iso-mdoc")
data class IsoMdocResponse(
    @SerialName("data")
    val data: DCAPIResponse,
    @SerialName("origin")
    override val origin: String,
) : DigitalCredentialInterface()


// TODO this is essentially a copy of ResponseParametersFrom.DcApi
@Serializable
@SerialName("openid4vp-v1-signed")
data class Oid4VpResponseSigned(
    @SerialName("data")
    val data: AuthenticationResponseParameters,
    @SerialName("origin")
    override val origin: String,
) : DigitalCredentialInterface()

@Serializable
@SerialName("openid4vp-v1-unsigned")
data class Oid4VpResponseUnsigned(
    @SerialName("data")
    val data: AuthenticationResponseParameters,
    @SerialName("origin")
    override val origin: String,
) : DigitalCredentialInterface()
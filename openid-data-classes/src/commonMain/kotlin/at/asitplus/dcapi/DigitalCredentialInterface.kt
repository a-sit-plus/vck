package at.asitplus.dcapi

import at.asitplus.dcapi.request.ExchangeProtocolIdentifier
import at.asitplus.openid.AuthenticationResponseParameters
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonClassDiscriminator

@Serializable
@JsonClassDiscriminator("protocol")
sealed class DigitalCredentialInterface {
    abstract val protocol: ExchangeProtocolIdentifier
    abstract val origin: String?
}

@Serializable
@SerialName("org-iso-mdoc")
data class IsoMdocResponse(
    @SerialName("data")
    val data: DCAPIResponse,
    @SerialName("origin")
    override val origin: String? = null,
) : DigitalCredentialInterface() {
    override val protocol: ExchangeProtocolIdentifier
        get() = ExchangeProtocolIdentifier.ISO_MDOC_ANNEX_C
}


@Serializable
@JsonClassDiscriminator("protocol")
sealed interface OpenId4VpResponse {
    val protocol: ExchangeProtocolIdentifier
    val data: AuthenticationResponseParameters
    val origin: String?
}

@Serializable
@SerialName("openid4vp-v1-signed")
data class OpenId4VpResponseSigned(
    @SerialName("data")
    override val data: AuthenticationResponseParameters,
    @SerialName("origin")
    override val origin: String? = null,
) : DigitalCredentialInterface(), OpenId4VpResponse {
    override val protocol: ExchangeProtocolIdentifier
        get() = ExchangeProtocolIdentifier.OPENID4VP_V1_SIGNED
}

@Serializable
@SerialName("openid4vp-v1-unsigned")
data class OpenId4VpResponseUnsigned(
    @SerialName("data")
    override val data: AuthenticationResponseParameters,
    @SerialName("origin")
    override val origin: String? = null,
) : DigitalCredentialInterface(), OpenId4VpResponse {
    override val protocol: ExchangeProtocolIdentifier
        get() = ExchangeProtocolIdentifier.OPENID4VP_V1_UNSIGNED
}

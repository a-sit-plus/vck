package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.data.rfc7519.jwt.headers.JwtTypeHeaderParameterSpecification
import at.asitplus.wallet.lib.data.rfc9596.cose.headers.CoseTypeHeaderParameterSpecification
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.CborLabel

@Serializable
data class StatusListTokenHeader(
    @SerialName(JwtTypeHeaderParameterSpecification.NAME)
    @CborLabel(CoseTypeHeaderParameterSpecification.KEY)
    val type: String,
)

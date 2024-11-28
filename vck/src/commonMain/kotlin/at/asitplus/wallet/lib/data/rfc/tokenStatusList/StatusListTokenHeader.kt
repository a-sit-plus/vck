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
) {
    companion object {
        init {
            // TODO: Move to tests?
            // Sanity check that the serial names are compatible between formats
            listOf(
                "typ" to mapOf(
                    "Json" to JwtTypeHeaderParameterSpecification.NAME,
                    "Cbor" to CoseTypeHeaderParameterSpecification.NAME,
                ),
            ).forEach { (memberName, serialLabels) ->
                if(serialLabels.values.distinct().size != 1) {
                    throw IllegalStateException("Member `$memberName` has different serial names between the following formats: [${serialLabels.keys.joinToString(", ") { it }}]")
                }
            }
        }
    }
}

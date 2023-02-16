package at.asitplus.wallet.lib.jws

import kotlinx.serialization.Serializable

@Serializable(with = EcCurveSerializer::class)
enum class EcCurve(val jwkName: String) {

    SECP_256_R_1("P-256");

    val keyLengthBits
        get() = when (this) {
            SECP_256_R_1 -> 256
        }

    val coordinateLengthBytes
        get() = when (this) {
            SECP_256_R_1 -> 32
        }

    val signatureLengthBytes
        get() = when (this) {
            SECP_256_R_1 -> 32
        }

}
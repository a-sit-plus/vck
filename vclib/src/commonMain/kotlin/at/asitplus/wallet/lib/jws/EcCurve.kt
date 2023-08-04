package at.asitplus.wallet.lib.jws

import kotlinx.serialization.Serializable

@Serializable(with = EcCurveSerializer::class)
enum class EcCurve(val jwkName: String) {

    SECP_256_R_1("P-256"),
    SECP_384_R_1("P-384"),
    SECP_521_R_1("P-521");

    val keyLengthBits
        get() = when (this) {
            SECP_256_R_1 -> 256
            SECP_384_R_1 -> 384
            SECP_521_R_1 -> 521
        }

    val coordinateLengthBytes
        get() = when (this) {
            SECP_256_R_1 -> 256 / 8
            SECP_384_R_1 -> 384 / 8
            SECP_521_R_1 -> 521 / 8
        }

    val signatureLengthBytes
        get() = when (this) {
            SECP_256_R_1 -> 256 / 8
            SECP_384_R_1 -> 384 / 8
            SECP_521_R_1 -> 521 / 8
        }

}
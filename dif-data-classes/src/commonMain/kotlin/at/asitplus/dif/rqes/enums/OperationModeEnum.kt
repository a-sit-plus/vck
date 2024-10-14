package at.asitplus.dif.rqes.enums

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Used as part of [SignatureRequestParameters]
 */
@Suppress("unused")
@Serializable
enum class OperationModeEnum {
    /**
     * “A”: an asynchronous operation mode is requested.
     */
    @SerialName("A")
    ASYNCHRONOUS,

    /**
     * “S”: a synchronous operation mode is requested.
     */
    @SerialName("S")
    SYNCHRONOUS,
}
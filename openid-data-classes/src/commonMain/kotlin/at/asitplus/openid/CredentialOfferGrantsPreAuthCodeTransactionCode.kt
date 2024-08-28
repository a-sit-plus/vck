package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CredentialOfferGrantsPreAuthCodeTransactionCode(
    /**
     * OID4VCI: OPTIONAL. String specifying the input character set. Possible values are `numeric` (only digits) and
     * `text` (any characters). The default is `numeric`.
     */
    @SerialName("input_mode")
    val inputMode: String? = "numeric",

    /**
     * OID4VCI: OPTIONAL. Integer specifying the length of the Transaction Code. This helps the Wallet to render the
     * input screen and improve the user experience.
     */
    @SerialName("length")
    val length: Int? = null,

    /**
     * OID4VCI: OPTIONAL. String containing guidance for the Holder of the Wallet on how to obtain the Transaction
     * Code, e.g., describing over which communication channel it is delivered.
     */
    @SerialName("description")
    val description: String? = null,
)
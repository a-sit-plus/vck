package at.asitplus.dif

import at.asitplus.dif.rqes.Base64URLTransactionDataSerializer
import at.asitplus.dif.rqes.TransactionDataEntry
import com.benasher44.uuid.uuid4
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Presentation Exchange v2.1.1](https://identity.foundation/presentation-exchange/spec/v2.1.1/#term:presentation-definition)
 */
@Serializable
data class InputDescriptor(
    @SerialName("id")
    val id: String,
    @SerialName("group")
    val group: String? = null,
    @SerialName("name")
    val name: String? = null,
    @SerialName("purpose")
    val purpose: String? = null,
    @SerialName("format")
    val format: FormatHolder? = null,
    /**
     * Transaction Data is REQUIRED in LSP UC5
     */
    @SerialName("transaction_data")
    val transactionData: List<@Serializable(Base64URLTransactionDataSerializer::class) TransactionDataEntry>? = null,
    @SerialName("constraints")
    val constraints: Constraint? = null,
) {
    constructor(name: String, constraints: Constraint? = null) : this(
        id = uuid4().toString(),
        name = name,
        constraints = constraints,
    )
}

package at.asitplus.rqes

import at.asitplus.dif.Constraint
import at.asitplus.dif.FormatHolder
import at.asitplus.dif.InputDescriptor
import at.asitplus.rqes.collection_entries.TransactionData
import at.asitplus.rqes.serializers.Base64URLTransactionDataSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class QesInputDescriptor(
    @SerialName("id")
    override val id: String,
    @SerialName("group")
    override val group: String? = null,
    @SerialName("name")
    override val name: String? = null,
    @SerialName("purpose")
    override val purpose: String? = null,
    @SerialName("format")
    override val format: FormatHolder? = null,
    @SerialName("constraints")
    override val constraints: Constraint? = null,
    @Deprecated("Obsoleted by OpenID4VP draft 23. Remove after UC5 piloting")
    @SerialName("transaction_data")
    val transactionData: List<@Serializable(Base64URLTransactionDataSerializer::class) TransactionData>? = null,
) : InputDescriptor

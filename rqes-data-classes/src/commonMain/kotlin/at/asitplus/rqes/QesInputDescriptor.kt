package at.asitplus.rqes

import at.asitplus.dif.Constraint
import at.asitplus.dif.FormatHolder
import at.asitplus.dif.InputDescriptor
import at.asitplus.openid.TransactionData
import at.asitplus.openid.TransactionDataBase64Url
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class QesInputDescriptor(
    @SerialName("id")
    override val id: String,
    @SerialName("group")
    val groups: Collection<String>? = null,
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
    val transactionData: List<TransactionDataBase64Url>? = null,
) : InputDescriptor {

    @Deprecated("To be replaced with groups, see #267")
    override val group: String?
        get() = groups?.firstOrNull()

}

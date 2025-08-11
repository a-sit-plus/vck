package at.asitplus.rqes

import at.asitplus.dif.Constraint
import at.asitplus.dif.FormatHolder
import at.asitplus.openid.TransactionDataBase64Url
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


@Deprecated("Module will be removed in the future", ReplaceWith("at.asitplus.csc.InputDescriptor"))
interface InputDescriptor

@Serializable
@Deprecated("Module will be removed in the future; Please switch to OpenId4VP QES Flow", ReplaceWith("at.asitplus.dif.DifInputDescriptor"))
data class QesInputDescriptor(
    @SerialName("id")
     val id: String,
    @SerialName("group")
    val groups: Collection<String>? = null,
    @SerialName("name")
     val name: String? = null,
    @SerialName("purpose")
     val purpose: String? = null,
    @SerialName("format")
     val format: FormatHolder? = null,
    @SerialName("constraints")
     val constraints: Constraint? = null,
    @Deprecated("Obsoleted by OpenID4VP draft 23. Remove after UC5 piloting")
    @SerialName("transaction_data")
    val transactionData: List<TransactionDataBase64Url>? = null,
) : InputDescriptor {

    @Deprecated("To be replaced with groups, see #267")
     val group: String?
        get() = groups?.firstOrNull()

}

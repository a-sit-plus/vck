package at.asitplus.csc.datamodel.documents

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** Identifies whether document bytes are the signer's original or formatted document. */
@Serializable
enum class DocumentType {
    @SerialName("sod")
    SOD,

    @SerialName("sfd")
    SFD,
}
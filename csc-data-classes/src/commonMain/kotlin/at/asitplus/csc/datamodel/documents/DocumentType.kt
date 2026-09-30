package at.asitplus.csc.datamodel.documents

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** CSC Data Model 1.0.0 section 8.1: Identifies original or formatted document bytes. */
@Serializable
enum class DocumentType {
    @SerialName("sod")
    SOD,

    @SerialName("sfd")
    SFD,
}

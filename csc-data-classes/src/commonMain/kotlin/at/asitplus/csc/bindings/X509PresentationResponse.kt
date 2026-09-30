package at.asitplus.csc.bindings

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** CSC Data Model Bindings 1.0.0 section 8.2. */
@Serializable
data class X509PresentationResponse(
    /** CSC Data Model Bindings 8.2: Inline QES response, when returned with the X.509 presentation. */
    @SerialName("qes")
    val qes: QesResponse? = null,
)

package at.asitplus.csc.bindings

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/**
 * CSC Data Model Bindings 1.0.0 section 8.2: CONDITIONAL
 * X.509 presentation response.
 */
@Serializable
data class X509PresentationResponse(
    /**
     * CSC Data Model Bindings 1.0.0 section 8.2: CONDITIONAL
     * Required when the QES response is inline and the request has no responseURI; otherwise omit.
     */
    @SerialName("qes")
    val qes: QesResponse? = null,
)

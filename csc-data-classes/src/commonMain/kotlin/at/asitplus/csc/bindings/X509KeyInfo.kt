package at.asitplus.csc.bindings

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** CSC Data Model Bindings 1.0.0 section 8.1.1. */
@Serializable
data class X509KeyInfo(
    /**
     * CSC Data Model Bindings 1.0.0 section 8.1.1: REQUIRED
     * Public-key algorithm OID.
     */
    @SerialName("algo")
    val algo: String,
    /**
     * CSC Data Model Bindings 1.0.0 section 8.1.1: CONDITIONAL
     * Required for non-elliptic-curve algorithms; MUST be omitted for elliptic-curve algorithms.
     */
    @SerialName("len")
    val len: Int? = null,
    /**
     * CSC Data Model Bindings 1.0.0 section 8.1.1: CONDITIONAL
     * Required for elliptic-curve algorithms; MUST be omitted for other algorithms.
     */
    @SerialName("curve")
    val curve: String? = null,
)

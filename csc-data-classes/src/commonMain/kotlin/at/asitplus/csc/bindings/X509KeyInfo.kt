package at.asitplus.csc.bindings

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** CSC Data Model Bindings 1.0.0 section 8.1.1. */
@Serializable
data class X509KeyInfo(
    /** CSC Data Model Bindings 8.1.1: Public-key algorithm identifier. */
    @SerialName("algo")
    val algo: String,
    /** CSC Data Model Bindings 8.1.1: Optional public-key length in bits. */
    @SerialName("len")
    val len: Int? = null,
    /** CSC Data Model Bindings 8.1.1: Optional elliptic-curve name. */
    @SerialName("curve")
    val curve: String? = null,
)

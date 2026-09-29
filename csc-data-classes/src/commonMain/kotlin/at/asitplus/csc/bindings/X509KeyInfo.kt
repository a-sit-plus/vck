package at.asitplus.csc.bindings

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** CSC Data Model Bindings 1.0.0 section 8.1.1. */
@Serializable
data class X509KeyInfo(
    @SerialName("algo")
    val algo: String,
    @SerialName("len")
    val len: Int? = null,
    @SerialName("curve")
    val curve: String? = null,
)
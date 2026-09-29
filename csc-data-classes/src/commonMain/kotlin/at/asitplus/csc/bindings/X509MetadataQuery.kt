package at.asitplus.csc.bindings

import at.asitplus.csc.datamodel.basic.Hash
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** CSC Data Model Bindings 1.0.0 section 8.1. */
@Serializable
data class X509MetadataQuery(
    @SerialName("certificateFingerprints")
    val certificateFingerprints: List<Hash>? = null,
    @SerialName("certificatePolicies")
    val certificatePolicies: List<String> = emptyList(),
    @SerialName("keys")
    val keys: List<X509KeyInfo>? = null,
)

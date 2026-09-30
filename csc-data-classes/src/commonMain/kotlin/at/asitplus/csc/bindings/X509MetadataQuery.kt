package at.asitplus.csc.bindings

import at.asitplus.csc.datamodel.basic.Hash
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** CSC Data Model Bindings 1.0.0 section 8.1. */
@Serializable
data class X509MetadataQuery(
    /** CSC Data Model Bindings 8.1: Certificate fingerprints used to select an X.509 credential. */
    @SerialName("certificateFingerprints")
    val certificateFingerprints: List<Hash>? = null,
    /** CSC Data Model Bindings 8.1: Certificate policy OIDs required of the credential. */
    @SerialName("certificatePolicies")
    val certificatePolicies: List<String> = emptyList(),
    /** CSC Data Model Bindings 8.1: Public-key characteristics required of the credential. */
    @SerialName("keys")
    val keys: List<X509KeyInfo>? = null,
)

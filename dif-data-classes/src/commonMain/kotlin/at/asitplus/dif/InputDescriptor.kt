package at.asitplus.dif

/**
 * Input Descriptors are objects used to describe the
 * information a Verifier requires of a Holder.
 * All Input Descriptors MUST be satisfied,
 * unless otherwise specified by a Feature.
 */
interface InputDescriptor {
    /**
     * MUST contain an id property.
     * The value of the id property MUST be a string that
     * does not conflict with the id of another
     * Input Descriptor Object in the same
     * Presentation Definition and
     * SHOULD not conflict with any other id value
     * present in the same Presentation Definition.
     */
    val id: String

    /**
     * MAY contain a name property.
     * If present, its value SHOULD be a human-friendly name
     * that describes what the target schema represents.
     */
    val name: String?

    /**
     * MAY contain a purpose property.
     * If present, its value MUST be a string
     * that describes the purpose for which
     * the Claim's data is being requested.
     */
    val purpose: String?

    /**
     * MAY contain a format property.
     * If present, its value MUST be an object
     * with one or more properties matching
     * the registered Claim Format Designations
     */
    val format: FormatHolder?

    /**
     * MUST contain a constraints property. Its value MUST be an object composed as follows, and it MUST contain one of the allowed properties or Features
     */
    val constraints: Constraint?
}

/**
 * Features enable Verifiers to express,
 * and Holders to support, extended functionality
 * (relative to the base objects) by defining
 * one or more properties on one or more objects.
 */
sealed class InputDescriptorFeatures {
    interface GroupFeature {
        val group: String?
    }
}

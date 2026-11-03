package at.asitplus.etsi

interface SchemeExtension {
    /** Whether an unrecognized extension requires rejection of the list (TS 119 602, 6.3.17). */
    val isCritical: Boolean
}
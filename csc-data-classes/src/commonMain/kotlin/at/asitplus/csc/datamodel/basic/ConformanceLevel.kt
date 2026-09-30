package at.asitplus.csc.datamodel.basic

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/**
 * CSC Data Model 1.0.0:
 * The required signature conformance level
 */
@Suppress("unused")
@Serializable
enum class ConformanceLevel {

    /**
     * “AdES-B” SHALL be used to request the creation
     * of a baseline etsits level B signature
     */
    @SerialName("AdES-B")
    ADESB,

    /**
     * “AdES-B-B” SHALL be used to request the creation
     * of a baseline 191x2 level B signature
     */
    @SerialName("AdES-B-B")
    ADESBB,

    /**
     * “AdES-B-T” SHALL be used to request the creation
     * of a baseline 191x2 level T signature
     */
    @SerialName("AdES-B-T")
    ADESBT,

    /**
     * “AdES-B-LT” SHALL be used to request the creation
     * of a baseline 191x2 level LT signature
     */
    @SerialName("AdES-B-LT")
    ADESBLT,

    /**
     * “AdES-B-LTA” SHALL be used to request the creation
     * of a baseline 191x2 level LTA signature
     */
    @SerialName("AdES-B-LTA")
    ADESBLTA,

    /**
     * “AdES-T” SHALL be used to request the creation
     * of a baseline etsits level T signature
     */
    @SerialName("AdES-T")
    ADEST,

    /**
     * “AdES-LT” SHALL be used to request the creation
     * of a baseline etsits level LT signature
     */
    @SerialName("AdES-LT")
    ADESLT,

    /**
     * “AdES-LTA” SHALL be used to request the creation
     * of a baseline etsits level LTA signature.
     */
    @SerialName("AdES-LTA")
    ADESLTA
}

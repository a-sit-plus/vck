package at.asitplus.rqes.enums

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * CSC v2.0.0.2:
 * The required signature conformance level
 */
@Suppress("unused")
@Serializable
enum class ConformanceLevelEnum {

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
    @SerialName("AdES-T-LT")
    ADESTLT,

    /**
     * “AdES-LTA” SHALL be used to request the creation
     * of a baseline etsits level LTA signature.
     */
    @SerialName("AdES-T-LTA")
    ADESTLTA
}
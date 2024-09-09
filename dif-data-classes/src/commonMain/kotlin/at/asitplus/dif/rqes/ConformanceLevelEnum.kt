package at.asitplus.dif.rqes

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
     * “Ades-B” SHALL be used to request the creation
     * of a baseline etsits level B signature
     */
    @SerialName("Ades-B")
    ADESB,

    /**
     * “Ades-B-B” SHALL be used to request the creation
     * of a baseline 191x2 level B signature
     */
    @SerialName("Ades-B-B")
    ADESBB,

    /**
     * “Ades-B-T” SHALL be used to request the creation
     * of a baseline 191x2 level T signature
     */
    @SerialName("Ades-B-T")
    ADESBT,

    /**
     * “Ades-B-LT” SHALL be used to request the creation
     * of a baseline 191x2 level LT signature
     */
    @SerialName("Ades-B-LT")
    ADESBLT,

    /**
     * “Ades-B-LTA” SHALL be used to request the creation
     * of a baseline 191x2 level LTA signature
     */
    @SerialName("Ades-B-LTA")
    ADESBLTA,

    /**
     * “Ades-T” SHALL be used to request the creation
     * of a baseline etsits level T signature
     */
    @SerialName("Ades-T")
    ADEST,

    /**
     * “Ades-LT” SHALL be used to request the creation
     * of a baseline etsits level LT signature
     */
    @SerialName("Ades-T-LT")
    ADESTLT,

    /**
     * “Ades-LTA” SHALL be used to request the creation
     * of a baseline etsits level LTA signature.
     */
    @SerialName("Ades-T-LTA")
    ADESTLTA
}
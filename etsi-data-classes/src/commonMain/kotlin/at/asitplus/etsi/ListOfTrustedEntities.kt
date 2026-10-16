package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ListOfTrustedEntities(
    /** Metadata describing the list, its operator and its governing scheme (TS 119 602, 6.3). */
    @SerialName(SerialNames.LIST_AND_SCHEME_INFORMATION)
    val listAndSchemeInformation: ListAndSchemeInformation? = null,
    /** Trusted entities and their services recognized under the scheme (TS 119 602, 6.4). */
    @SerialName(SerialNames.TRUSTED_ENTITIES_LIST)
    val trustedEntitiesList: TrustedEntitiesList? = null,
) {
    init {
        listAndSchemeInformation?.historicalInformationPeriod?.takeIf {
            it != 0
        }?.let {
            trustedEntitiesList?.forEach {
                it.trustedEntityServices.forEach {
                    require(it.serviceInformation.serviceStatus != null) {
                        "When the HistoricalInformationPeriod component is present with a non-zero value, the ServiceStatus component shall be present."
                    }
                }
            }
        }
    }
    object SerialNames {
        /** Wire member name `ListAndSchemeInformation`. */
        const val LIST_AND_SCHEME_INFORMATION = "ListAndSchemeInformation"
        /** Wire member name `TrustedEntitiesList`. */
        const val TRUSTED_ENTITIES_LIST = "TrustedEntitiesList"
    }
}
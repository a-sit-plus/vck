package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ListOfTrustedEntities(
    @SerialName(SerialNames.LIST_AND_SCHEME_INFORMATION)
    val listAndSchemeInformation: ListAndSchemeInformation? = null,
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
        const val LIST_AND_SCHEME_INFORMATION = "ListAndSchemeInformation"
        const val TRUSTED_ENTITIES_LIST = "TrustedEntitiesList"
    }
}
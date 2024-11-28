package at.asitplus.wallet.lib.data.rfc.tokenStatusList.status

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.json.JsonObjectKey
import kotlinx.serialization.SerialName

/**
 * 6.2 Referenced Token in JOSE
 *
 * REQUIRED when the status list mechanism defined in this specification is used. It contains a reference to a Status List or Status List Token. It MUST at least contain the following claims:
 */
object JwtStatusListStatusMechanismSpecification : JwtStatusMechanismSpecification {
    const val NAME = "status_list"

    override val key: JsonObjectKey
        get() = NAME

    interface StatusMechanismProvider {
        @SerialName(NAME)
        @Suppress("PropertyName")
        val status_list: StatusListInfo?
    }

    val JwtStatusMechanismSpecification.Companion.status_list: JwtStatusListStatusMechanismSpecification
        get() = JwtStatusListStatusMechanismSpecification
}
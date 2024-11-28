package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.status.CwtStatusMechanismProvider
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.status.JwtStatusListStatusMechanismSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.status.JwtStatusMechanismProvider
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class Status(
    @SerialName(JwtStatusListStatusMechanismSpecification.NAME) val statusList: StatusListInfo
): JwtStatusMechanismProvider, CwtStatusMechanismProvider {
    init {
        JwtStatusMechanismProvider.validate(this)
        CwtStatusMechanismProvider.validate(this)
    }

    override val status_list: StatusListInfo
        get() = statusList
}
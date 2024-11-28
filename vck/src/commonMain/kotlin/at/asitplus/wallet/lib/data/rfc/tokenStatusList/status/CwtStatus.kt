package at.asitplus.wallet.lib.data.rfc.tokenStatusList.status

interface CwtStatus : CwtStatusListStatusMechanismSpecification.StatusMechanismProvider {
    companion object {
        fun validate(status: CwtStatus): Unit = status.run {
            val availableStatusMechanisms = listOfNotNull(
                status_list,
            )

            if (availableStatusMechanisms.isEmpty()) {
                throw IllegalArgumentException("Argument `status` MUST specify at least one reference to a status mechanism.")
            }
        }
    }
}
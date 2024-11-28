package at.asitplus.wallet.lib.data.rfc.tokenStatusList.status

interface JwtStatusMechanismProvider : JwtStatusListStatusMechanismSpecification.StatusMechanismProvider {
    companion object {
        fun validate(status: JwtStatusMechanismProvider): Unit = status.run {
            val availableStatusMechanisms = listOfNotNull(
                status_list,
            )

            if (availableStatusMechanisms.isEmpty()) {
                throw IllegalArgumentException("Argument `status` MUST specify at least one reference to a status mechanism.")
            }
        }
    }
}


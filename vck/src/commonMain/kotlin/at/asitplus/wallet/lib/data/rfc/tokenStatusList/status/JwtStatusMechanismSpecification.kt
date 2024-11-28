package at.asitplus.wallet.lib.data.rfc.tokenStatusList.status

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.json.JsonObjectKey

interface JwtStatusMechanismSpecification : StatusMechanismSpecification {
    companion object {
        val StatusMechanismSpecification.Companion.JwtStatusMechanismSpecifications: Companion
            get() = Companion
    }

    val key: JsonObjectKey
}
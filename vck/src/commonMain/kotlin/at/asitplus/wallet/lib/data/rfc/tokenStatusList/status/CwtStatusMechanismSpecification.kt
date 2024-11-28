package at.asitplus.wallet.lib.data.rfc.tokenStatusList.status

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cbor.CborTextString

interface CwtStatusMechanismSpecification : StatusMechanismSpecification {
    companion object {
        val StatusMechanismSpecification.Companion.CwtStatusMechanismSpecifications: Companion
            get() = Companion
    }

    val key: CborTextString
}
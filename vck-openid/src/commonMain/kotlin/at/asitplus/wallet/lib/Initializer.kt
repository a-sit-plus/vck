package at.asitplus.wallet.lib

import at.asitplus.openid.odcJsonSerializer
import at.asitplus.wallet.lib.data.serializerModuleCollection
import kotlinx.serialization.modules.overwriteWith


object Initializer {
    fun initOpenIdModule() {
        serializerModuleCollection = serializerModuleCollection.overwriteWith(odcJsonSerializer.serializersModule)
    }
}
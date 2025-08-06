package at.asitplus.wallet.lib.rqes

import at.asitplus.openid.odcJsonSerializer
import at.asitplus.wallet.lib.data.serializerModuleCollection
import kotlinx.serialization.modules.overwriteWith


object Initializer {
    fun initRqesModule() {
        serializerModuleCollection = serializerModuleCollection.overwriteWith(odcJsonSerializer.serializersModule)
    }
}


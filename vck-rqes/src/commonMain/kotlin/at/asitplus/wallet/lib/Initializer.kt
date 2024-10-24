package at.asitplus.wallet.lib

import at.asitplus.rqes.rdcJsonSerializer
import at.asitplus.wallet.lib.data.serializerModuleCollection
import kotlinx.serialization.modules.overwriteWith


object Initializer {
    fun initRqesModule() {
        serializerModuleCollection = serializerModuleCollection.overwriteWith(rdcJsonSerializer.serializersModule)
    }
}
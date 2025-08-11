package at.asitplus.wallet.lib.rqes

import at.asitplus.rqes.rdcJsonSerializer
import at.asitplus.wallet.lib.data.serializerModuleCollection
import kotlinx.serialization.modules.overwriteWith

@Deprecated("Module will be removed in the future. Use vck-openid instead!")
object Initializer {
    fun initRqesModule() {
        serializerModuleCollection = serializerModuleCollection.overwriteWith(rdcJsonSerializer.serializersModule)
    }
}


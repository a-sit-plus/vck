package at.asitplus.wallet.lib

import at.asitplus.wallet.lib.rqes.Initializer.initRqesModule
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier
import io.kotest.core.config.AbstractProjectConfig

class KotestConfig : AbstractProjectConfig() {
    init {
        Napier.takeLogarithm()
        Napier.base(DebugAntilog())
        initRqesModule()
        at.asitplus.wallet.mdl.Initializer.initWithVCK()
        at.asitplus.wallet.eupid.Initializer.initWithVCK()
    }
}
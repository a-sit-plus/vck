import at.asitplus.wallet.lib.Initializer.initOpenIdModule
import de.infix.testBalloon.framework.TestSession
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier

class ModuleTestSession : TestSession() {
    init {
        Napier.takeLogarithm()
        Napier.base(DebugAntilog())
        initOpenIdModule()
        at.asitplus.wallet.mdl.Initializer.initWithVCK()
        at.asitplus.wallet.eupid.Initializer.initWithVCK()
    }
}

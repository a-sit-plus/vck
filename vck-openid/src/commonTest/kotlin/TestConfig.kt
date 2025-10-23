import de.infix.testBalloon.framework.TestSession
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier

class ModuleTestSession : TestSession() {
    init {
        Napier.takeLogarithm()
        Napier.base(DebugAntilog())
        at.asitplus.wallet.eupid.Initializer.initWithVCK()
        at.asitplus.wallet.mdl.Initializer.initWithVCK()
    }
}

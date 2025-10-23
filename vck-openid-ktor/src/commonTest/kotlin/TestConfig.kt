import at.asitplus.wallet.eupid.Initializer
import de.infix.testBalloon.framework.TestSession
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier

class TestConfig : TestSession() {
    init {
        Napier.takeLogarithm()
        Napier.base(DebugAntilog())
        Initializer.initWithVCK()
        at.asitplus.wallet.mdl.Initializer.initWithVCK()
    }
}

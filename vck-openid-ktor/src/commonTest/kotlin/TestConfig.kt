import at.asitplus.testballoon.FreeSpec
import at.asitplus.wallet.eupid.Initializer

import de.infix.testBalloon.framework.core.TestSession
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testScope
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier

class TestConfig : TestSession(
    testConfig = DefaultConfiguration.invocation(de.infix.testBalloon.framework.core.TestConfig.Invocation.Concurrent)
        .testScope(isEnabled = false)
) {
    init {
        Napier.takeLogarithm()
        Napier.base(DebugAntilog())
        Initializer.initWithVCK()
        at.asitplus.wallet.mdl.Initializer.initWithVCK()
        FreeSpec.defaultTestNameMaxLength = 10 //work around Android test name length limit
        FreeSpec.defaultDisplayNameMaxLength = 32 //work around Android test name length limit
    }
}

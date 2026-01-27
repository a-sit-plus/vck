import at.asitplus.testballoon.FreeSpec

import de.infix.testBalloon.framework.core.TestSession
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testScope
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier
import kotlin.time.Duration.Companion.minutes


expect val testNameLengths: Pair<Int, Int>

class TestConfig : TestSession(
    testConfig = DefaultConfiguration.invocation(de.infix.testBalloon.framework.core.TestConfig.Invocation.Concurrent)
        .testScope(isEnabled = false)
) {
    init {
        Napier.takeLogarithm()
        Napier.base(DebugAntilog())
        at.asitplus.wallet.eupid.Initializer.initWithVCK()
        at.asitplus.wallet.mdl.Initializer.initWithVCK()
        FreeSpec.defaultTestNameMaxLength = testNameLengths.first //work around Android test name length limit
        FreeSpec.defaultDisplayNameMaxLength = testNameLengths.second //work around Android test name length limit
    }
}

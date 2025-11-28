import at.asitplus.testballoon.FreeSpec
import at.asitplus.wallet.eupid.Initializer
import de.infix.testBalloon.framework.core.TestInvocation
import de.infix.testBalloon.framework.core.TestSession
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testScope
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier
import kotlin.time.Duration.Companion.minutes

internal expect val testInvocation: TestInvocation

class TestConfig : TestSession(
    testConfig = DefaultConfiguration.invocation(testInvocation)
        .testScope(isEnabled = true, timeout = 20.minutes)
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

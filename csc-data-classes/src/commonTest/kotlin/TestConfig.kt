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
    }
}

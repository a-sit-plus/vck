import de.infix.testBalloon.framework.TestInvocation
import de.infix.testBalloon.framework.TestSession
import de.infix.testBalloon.framework.invocation
import de.infix.testBalloon.framework.testScope
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier
import kotlin.time.Duration.Companion.minutes

//Supercharge tests with concurrency!
class TestConfig : TestSession(
    testConfig = DefaultConfiguration.invocation(TestInvocation.CONCURRENT)
        .testScope(isEnabled = true, timeout = 20.minutes)
) {
    init {
        Napier.takeLogarithm()
        Napier.base(DebugAntilog())
    }
}
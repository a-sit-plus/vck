import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.MatrixTestDefaults
import de.infix.testBalloon.framework.core.TestSession
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier

class TestConfig : TestSession(
    testConfig = DefaultConfiguration.apply { MatrixTestDefaults { execution = ExecutionMode.Concurrent(8) } }
) {
    init {
        Napier.takeLogarithm()
        Napier.base(DebugAntilog())
    }
}


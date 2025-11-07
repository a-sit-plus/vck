import at.asitplus.testballoon.FreeSpec
import de.infix.testBalloon.framework.core.TestSession
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier


internal expect val testNameLimit: Int

class TestConfig : TestSession() {
    init {
        Napier.takeLogarithm()
        Napier.base(DebugAntilog())
        FreeSpec.maxLength = testNameLimit //work around Android test name length limit
    }
}

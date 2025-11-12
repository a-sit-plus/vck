import at.asitplus.testballoon.FreeSpec
import de.infix.testBalloon.framework.core.TestSession
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier

expect val testNameLengths: Pair<Int, Int>

class TestConfig : TestSession() {
    init {
        Napier.takeLogarithm()
        Napier.base(DebugAntilog())
        FreeSpec.defaultMaxLength = testNameLengths.first //work around Android test name length limit
        FreeSpec.defaultDisplayNameMaxLength = testNameLengths.second //work around Android test name length limit
    }
}

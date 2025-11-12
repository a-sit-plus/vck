import at.asitplus.testballoon.FreeSpec
import de.infix.testBalloon.framework.core.TestSession
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier



class TestConfig : TestSession() {
    init {
        Napier.takeLogarithm()
        Napier.base(DebugAntilog())
        FreeSpec.defaultMaxLength = 3 //work around Android test name length limit
    }
}

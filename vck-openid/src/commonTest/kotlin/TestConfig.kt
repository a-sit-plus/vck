import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.MatrixTestDefaults
import de.infix.testBalloon.framework.core.TestSession
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier


expect val testNameLengths: Pair<Int, Int>

class TestConfig : TestSession(
    testConfig = DefaultConfiguration.apply {
        MatrixTestDefaults {
            execution = ExecutionMode.Concurrent(8)
            defaultTestNameMaxLength = testNameLengths.first
        }
    }
) {
    init {
        Napier.takeLogarithm()
        Napier.base(DebugAntilog())
        at.asitplus.wallet.eupid.Initializer.initWithVCK()
        at.asitplus.wallet.eupidsdjwt.Initializer.initWithVCK()
        at.asitplus.wallet.mdl.Initializer.initWithVCK()
    }
}

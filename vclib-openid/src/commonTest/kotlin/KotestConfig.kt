import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier
import io.kotest.core.config.AbstractProjectConfig

object KotestConfig : AbstractProjectConfig() {
    init {
        Napier.takeLogarithm()
        Napier.base(DebugAntilog())
    }
}
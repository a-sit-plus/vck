import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier
import io.kotest.core.config.AbstractProjectConfig
import io.kotest.core.names.DuplicateTestNameMode

class KotestConfig : AbstractProjectConfig() {
    init {
        Napier.base(DebugAntilog())
    }

    override val duplicateTestNameMode: DuplicateTestNameMode?
        get() = DuplicateTestNameMode.Error

}
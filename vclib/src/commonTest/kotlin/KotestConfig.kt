import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier
import io.kotest.core.config.AbstractProjectConfig
import io.kotest.core.names.DuplicateTestNameMode

object KotestConfig : AbstractProjectConfig() {
    init {
        Napier.base(DebugAntilog())
    }

    override var displayFullTestPath: Boolean?
        get() = false
        set(value) {}

    override val duplicateTestNameMode: DuplicateTestNameMode?
        get() = DuplicateTestNameMode.Error

}
package at.asitplus.wallet.lib

import at.asitplus.test.XmlReportingProjectConfig
import at.asitplus.wallet.eupid.Initializer
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier

/** Wires KMP JUnit XML reporting */
class ProjectConfig : XmlReportingProjectConfig() {
    init {
        Napier.takeLogarithm()
        Napier.base(DebugAntilog())
        Initializer.initWithVCK()
    }
}
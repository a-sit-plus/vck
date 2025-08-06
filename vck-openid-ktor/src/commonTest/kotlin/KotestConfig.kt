package io.kotest.provided

import at.asitplus.test.XmlReportingProjectConfig
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier

/** Wires KMP JUnit XML reporting */
class ProjectConfig : XmlReportingProjectConfig() {
    init {
        Napier.takeLogarithm()
        Napier.base(DebugAntilog())
        at.asitplus.wallet.eupid.Initializer.initWithVCK()
        at.asitplus.wallet.mdl.Initializer.initWithVCK()
    }
}
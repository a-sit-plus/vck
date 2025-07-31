package io.kotest.provided
import at.asitplus.test.XmlReportingProjectConfig
import at.asitplus.test.JUnitXmlReporter
import at.asitplus.wallet.lib.rqes.Initializer.initRqesModule
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier
import io.kotest.core.config.AbstractProjectConfig
import io.kotest.core.extensions.Extension

/** Wires KMP JUnit XML reporting */
class ProjectConfig : XmlReportingProjectConfig() {
    init {
        Napier.takeLogarithm()
        Napier.base(DebugAntilog())
        initRqesModule()
        at.asitplus.wallet.eupid.Initializer.initWithVCK()
    }
}
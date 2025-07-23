package io.kotest.provided
import at.asitplus.test.XmlReportingProjectConfig
import at.asitplus.test.JUnitXmlReporter
import at.asitplus.wallet.lib.Initializer.initOpenIdModule
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier
import io.kotest.core.config.AbstractProjectConfig
import io.kotest.core.extensions.Extension

/** Wires KMP JUnit XML reporting */
class ProjectConfig : XmlReportingProjectConfig() {
    init {
        Napier.takeLogarithm()
        Napier.base(DebugAntilog())
        initOpenIdModule()
        at.asitplus.wallet.eupid.Initializer.initWithVCK()
        at.asitplus.wallet.mdl.Initializer.initWithVCK()
    }
}
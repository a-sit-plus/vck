package at.asitplus.wallet.lib

import io.kotest.common.Platform
import io.kotest.common.platform
import io.kotest.core.spec.style.scopes.ContainerScope

fun <T> ContainerScope.nameHack(it: T) =
    if (platform == Platform.JVM) testCase.name.testName + " → " + it else it.toString()

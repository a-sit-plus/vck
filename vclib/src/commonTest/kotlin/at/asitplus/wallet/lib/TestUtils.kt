package at.asitplus.wallet.lib

import io.kotest.core.Platform
import io.kotest.core.platform
import io.kotest.core.spec.style.scopes.ContainerScope
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid


fun uuid4() = @OptIn(ExperimentalUuidApi::class) Uuid.random().toString()

fun <T> ContainerScope.nameHack(it: T) =
    if (platform == Platform.JVM) testCase.name.testName + " → " + it else it.toString()

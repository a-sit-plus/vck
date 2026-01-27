package at.asitplus.wallet.lib

import io.kotest.common.Platform
import io.kotest.common.platform
import io.kotest.core.spec.style.scopes.ContainerScope
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid


fun uuid4() = @OptIn(ExperimentalUuidApi::class) Uuid.random().toString()

fun <T> ContainerScope.nameHack(it: T) =
    if (platform == Platform.JVM) testCase.name.name + " → " + it else it.toString()

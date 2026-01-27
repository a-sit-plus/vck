package test

import io.kotest.core.spec.style.FreeSpec
import kotlin.experimental.ExperimentalNativeApi


@OptIn(ExperimentalNativeApi::class)
class `iOSOnlyTest` : FreeSpec({ "should run on on ${Platform}"{} })
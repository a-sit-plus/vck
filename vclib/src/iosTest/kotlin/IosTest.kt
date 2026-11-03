package test

import at.asitplus.testballoon.matrix.matrixSuite
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.Platform


@OptIn(ExperimentalNativeApi::class)
val `iOSOnlyTest` by matrixSuite { "should run on ${Platform}"{} }
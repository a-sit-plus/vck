package at.asitplus.wallet

import at.asitplus.test.Target
import at.asitplus.testballoon.matrix.*
import at.asitplus.testballoon.matrix.matrixSuite
import kotlin.experimental.ExperimentalNativeApi

@OptIn(ExperimentalNativeApi::class)
val iosOnlyTest by matrixSuite { "should work on ${Target.current}" { } }
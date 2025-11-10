package at.asitplus.wallet

import at.asitplus.test.Target
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import kotlin.experimental.ExperimentalNativeApi

@OptIn(ExperimentalNativeApi::class)
val iosOnlyTest by testSuite { "should run on on ${Target.current}" {} }
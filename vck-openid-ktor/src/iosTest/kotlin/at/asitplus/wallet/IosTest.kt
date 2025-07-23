package at.asitplus.wallet

import at.asitplus.test.FreeSpec
import kotlin.experimental.ExperimentalNativeApi

@OptIn(ExperimentalNativeApi::class)
class iosOnlyTest : FreeSpec({ "should run on on ${Platform}"{} })
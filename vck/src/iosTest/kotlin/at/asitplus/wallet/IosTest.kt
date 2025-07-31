package at.asitplus.wallet
import io.kotest.core.spec.style.FreeSpec
import kotlin.experimental.ExperimentalNativeApi

@OptIn(ExperimentalNativeApi::class)
class iosOnlyTest : FreeSpec({ "should run on on ${Platform}"{} })
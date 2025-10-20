package at.asitplus.wallet
import de.infix.testBalloon.framework.testSuite
import at.asitplus.testballoon.*
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.experimental.ExperimentalNativeApi

@OptIn(ExperimentalNativeApi::class)
class iosOnlyTest by testSuite{ "should run on on ${Platform}"{} })
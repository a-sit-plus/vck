import io.kotest.core.spec.style.FreeSpec
import kotlin.experimental.ExperimentalNativeApi

@OptIn(ExperimentalNativeApi::class)
class `iOS-Only Test` : FreeSpec({ "should run on on ${Platform}"{} })
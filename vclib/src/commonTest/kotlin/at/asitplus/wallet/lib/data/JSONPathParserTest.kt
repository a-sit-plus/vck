package at.asitplus.wallet.lib.data

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.ints.shouldBeExactly
import io.kotest.matchers.types.shouldBeInstanceOf

class JSONPathParserTest : FreeSpec({
    "Root selector is retrieved without exceptions" {
        val selectors = JSONPathParser("$").getSelectors()
        selectors.size shouldBeExactly 1
        selectors.get(0).shouldBeInstanceOf<JsonPathSelector.RootSelector>()
    }
})

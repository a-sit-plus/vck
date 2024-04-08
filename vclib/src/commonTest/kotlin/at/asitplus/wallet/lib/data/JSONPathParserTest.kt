package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.agent.toJsonElement
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.ints.shouldBeExactly
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonPrimitive

class JSONPathParserTest : FreeSpec({
    "Root selector is retrieved without exceptions" {
        val selectors = JSONPathParser("$").getSelectors()
        selectors.size shouldBeExactly 1
        selectors.get(0).shouldBeInstanceOf<JsonPathSelector.RootSelector>()
    }
    "Dot selector bevahes the same as index selector for member names" {
        val selectors1 = JSONPathParser("\$['mdoc'].doctype").getSelectors()
        val selectors2 = JSONPathParser("\$.mdoc.doctype").getSelectors()

        selectors1.size shouldBeExactly 3
        selectors2.size shouldBeExactly 3

        selectors1.get(0).shouldBeInstanceOf<JsonPathSelector.RootSelector>()
        selectors2.get(0).shouldBeInstanceOf<JsonPathSelector.RootSelector>()

        selectors1.get(1).shouldBeInstanceOf<JsonPathSelector.IndexSelector>()
        (selectors1.get(1) as JsonPathSelector.IndexSelector).memberName shouldBe "mdoc"
        selectors2.get(1).shouldBeInstanceOf<JsonPathSelector.DotSelector>()
        (selectors2.get(1) as JsonPathSelector.DotSelector).objectMemberName shouldBe "mdoc"

        selectors1.get(2).shouldBeInstanceOf<JsonPathSelector.DotSelector>()
        selectors2.get(2).shouldBeInstanceOf<JsonPathSelector.DotSelector>()
    }
})

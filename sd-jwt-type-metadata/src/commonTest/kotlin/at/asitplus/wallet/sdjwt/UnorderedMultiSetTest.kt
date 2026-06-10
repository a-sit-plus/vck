package at.asitplus.wallet.sdjwt

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

@Suppress("unused")
val UnorderedMultiSetTest by matrixSuite {
    test("order does not matter for equality, but multiplicity does") {
        UnorderedMultiSet<Nothing>() shouldBe UnorderedMultiSet<Nothing>()
        UnorderedMultiSet(listOf(1)).apply {
            this shouldBe UnorderedMultiSet(listOf(1))
            this shouldNotBe UnorderedMultiSet(listOf(2))
            this shouldNotBe UnorderedMultiSet(emptyList<Nothing>())
        }
        UnorderedMultiSet(1, 2).apply {
            this shouldNotBe UnorderedMultiSet(emptyList<Nothing>())
            this shouldNotBe UnorderedMultiSet(listOf(1))
            this shouldNotBe UnorderedMultiSet(listOf(2))
            this shouldBe UnorderedMultiSet(1, 2)
            this shouldBe UnorderedMultiSet(2, 1)
            this shouldNotBe UnorderedMultiSet(1, 1)
            this shouldNotBe UnorderedMultiSet(2, 2)
        }
        UnorderedMultiSet(1, 1).apply {
            this shouldNotBe UnorderedMultiSet(emptyList<Nothing>())
            this shouldNotBe UnorderedMultiSet(listOf(1))
            this shouldNotBe UnorderedMultiSet(listOf(2))
            this shouldNotBe UnorderedMultiSet(1, 2)
            this shouldNotBe UnorderedMultiSet(2, 1)
            this shouldNotBe UnorderedMultiSet(2, 2)
            this shouldBe UnorderedMultiSet(1, 1)
        }
        UnorderedMultiSet(1, 1, 2).apply {
            this shouldNotBe UnorderedMultiSet(emptyList<Nothing>())
            this shouldNotBe UnorderedMultiSet(listOf(1))
            this shouldNotBe UnorderedMultiSet(listOf(2))
            this shouldNotBe UnorderedMultiSet(1, 2)
            this shouldNotBe UnorderedMultiSet(2, 1)
            this shouldNotBe UnorderedMultiSet(2, 2)
            this shouldNotBe UnorderedMultiSet(1, 1)
            this shouldBe UnorderedMultiSet(1, 1, 2)
            this shouldBe UnorderedMultiSet(1, 2, 1)
            this shouldBe UnorderedMultiSet(2, 1, 1)
            this shouldNotBe UnorderedMultiSet(1, 1, 1)
            this shouldNotBe UnorderedMultiSet(1, 2, 2)
            this shouldNotBe UnorderedMultiSet(2, 1, 2)
            this shouldNotBe UnorderedMultiSet(2, 2, 1)
            this shouldNotBe UnorderedMultiSet(2, 2, 2)
        }
    }
}


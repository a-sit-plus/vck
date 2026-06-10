import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

val alibi by matrixSuite {
    test("Tests are working") {
        true shouldBe true
    }
}
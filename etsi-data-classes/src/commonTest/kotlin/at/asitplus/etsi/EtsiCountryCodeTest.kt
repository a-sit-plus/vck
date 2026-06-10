package at.asitplus.etsi

import at.asitplus.testballoon.matrix.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import kotlin.getValue

@Suppress("unused")
val EtsiCountryCodeTest by matrixSuite {
    testSuite("must all be uppercase") {
        listOf("a", "aA").asData() test {
            shouldThrow<IllegalArgumentException> {
                EtsiCountryCode(it)
            }
        }
        listOf("A", "AA", "EU", "UK", "EL").asData() test {
            EtsiCountryCode(it)
        }
    }
}
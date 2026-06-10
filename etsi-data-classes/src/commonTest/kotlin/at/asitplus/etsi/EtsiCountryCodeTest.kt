package at.asitplus.etsi

import at.asitplus.testballoon.matrix.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import kotlin.getValue

@Suppress("unused")
val EtsiCountryCodeTest by matrixSuite {
    testSuite("must all be uppercase") {
        data(listOf("a", "aA")) test {
            shouldThrow<IllegalArgumentException> {
                EtsiCountryCode(it)
            }
        }
        data(listOf("A", "AA", "EU", "UK", "EL")) test {
            EtsiCountryCode(it)
        }
    }
}
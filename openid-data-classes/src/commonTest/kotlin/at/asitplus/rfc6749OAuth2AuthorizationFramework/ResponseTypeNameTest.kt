package at.asitplus.rfc6749OAuth2AuthorizationFramework

import at.asitplus.testballoon.matrix.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow

@Suppress("unused")
val ResponseTypeNameTest by matrixSuite {
    "empty string is not valid" {
        shouldThrow<IllegalArgumentException> {
            ResponseTypeName("")
        }
    }
}
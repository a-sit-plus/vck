package at.asitplus.rfc6749OAuth2AuthorizationFramework

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow

@Suppress("unused")
val ResponseTypeNameTest by testSuite {
    "empty string is not valid" {
        shouldThrow<IllegalArgumentException> {
            ResponseTypeName("")
        }
    }
}
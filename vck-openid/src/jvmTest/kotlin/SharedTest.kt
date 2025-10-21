import at.asitplus.test.Target
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite

val `Shared Andoid JVM Test` by testSuite { "should work on ${Target.current}" { } }
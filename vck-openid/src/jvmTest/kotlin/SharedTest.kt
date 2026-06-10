import at.asitplus.test.Target
import at.asitplus.testballoon.matrix.matrixSuite

val `Shared Andoid JVM Test` by matrixSuite { "should work on ${Target.current}" { } }
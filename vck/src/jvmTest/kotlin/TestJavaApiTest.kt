import at.asitplus.testballoon.matrix.matrixSuite

val TestJavaApiTest by matrixSuite {
    "creates StatusListInfo through the Java API" {
        TestJavaApi().createsStatusListInfoFromJavaApi()
    }
}

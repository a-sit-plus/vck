package at.asitplus.wallet.lib.data

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import com.benasher44.uuid.uuid4

val CredentialPresentationRequestSerializerTest by matrixSuite {
    /*
    DCQLQuery is currently a `value class` where the serializer flattens the structure.
    Therefore, identifying the type based on the serial name `dcqlQuery` does not work.
    As long as we use `value class` the identifying should happen with the serial name `credentials`
     */
    test("Test flattened DCQLQuery") {
        val unflattened = """
        {
          "dcqlQuery": {
              "credentials" : [ {
                "id" : "${uuid4()}",
                "meta" : {
                  "doctype_value" : "eu.europa.ec.eudi.pid.1"
                },
                "claims" : [ {
                  "path" : [ "eu.europa.ec.eudi.pid.1", "family_name" ]
                }, {
                  "path" : [ "eu.europa.ec.eudi.pid.1", "given_name" ]
                }],
                "format" : "mso_mdoc"
              } ]
          }
        }
    """.trimIndent()

        val flattened = """
        {
          "credentials" : [ {
            "id" : "${uuid4()}",
            "meta" : {
              "doctype_value" : "eu.europa.ec.eudi.pid.1"
            },
            "claims" : [ {
              "path" : [ "eu.europa.ec.eudi.pid.1", "family_name" ]
            }, {
              "path" : [ "eu.europa.ec.eudi.pid.1", "given_name" ]
            }],
            "format" : "mso_mdoc"
          } ]
        }
        """.trimIndent()

        require(runCatching { joseCompliantSerializer.decodeFromString<CredentialPresentationRequest>(flattened) }.isSuccess)
        require(runCatching { joseCompliantSerializer.decodeFromString<CredentialPresentationRequest>(unflattened) }.isFailure)
    }
}

package at.asitplus.wallet.openid.dcql

import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.procedures.dcql.DCQLQueryAdapter
import de.infix.testBalloon.framework.testSuite
import at.asitplus.testballoon.*
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.maps.shouldHaveSize
import kotlinx.serialization.json.Json

val DCQLQueryProcedureAdapterTest by testSuite {
    "from bug issue 318" {

        val validator = Validator()
        val issuerCredentialStore = InMemoryIssuerCredentialStore()
        val holderCredentialStore = InMemorySubjectCredentialStore()
        val issuerIdentifier = "https://issuer.example.com/"
        val issuer = IssuerAgent(
            issuerCredentialStore = issuerCredentialStore,
            identifier = issuerIdentifier.toUri(),
            randomSource = RandomSource.Default
        )

        val holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
        val holder = HolderAgent(
            keyMaterial = holderKeyMaterial,
            subjectCredentialStore = holderCredentialStore,
            validator = validator,
        )
        val credential = holder.storeCredential(
            issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    SD_JWT,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        ).getOrThrow()

        val dcqlQuery = Json.decodeFromString<DCQLQuery>(
            """
              {
                "credential_sets": [
                  {
                    "purpose": "To obtain e-prescription, we need to verify your identity.",
                    "options": [
                      [
                        "pid_sd_jwt"
                      ]
                    ]
                  }
                ],
                "credentials": [
                  {
                    "id": "pid_sd_jwt",
                    "format": "vc+sd-jwt",
                    "meta": {
                      "vct_values": [
                        "AtomicAttribute2023"
                      ]
                    },
                    "claims": [
                      {
                        "path": [
                          "${ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME}"
                        ]
                      },
                      {
                        "path": [
                          "iss"
                        ],
                        "values": [
                          "$issuerIdentifier"
                        ]
                      }
                    ]
                  }
                ]
              }
            """.trimIndent()
        )

        DCQLQueryAdapter(dcqlQuery).select(
            credentials = listOf(credential)
        ).getOrThrow().credentialQueryMatches shouldHaveSize 1
    }
}
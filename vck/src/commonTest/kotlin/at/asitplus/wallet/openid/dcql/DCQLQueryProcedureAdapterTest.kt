package at.asitplus.wallet.openid.dcql

import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.signum.indispensable.asn1.Asn1Element.Tag.Template.Companion.without
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1OctetString
import at.asitplus.signum.indispensable.asn1.CONSTRUCTED
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.authorityKeyIdentifier_2_5_29_35
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.OctetString
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.Sequence
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.procedures.dcql.AuthorityKeyIdentifier
import at.asitplus.wallet.lib.procedures.dcql.DCQLQueryAdapter
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.maps.shouldHaveSize
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json
import kotlin.random.Random

val DCQLQueryProcedureAdapterTest by testSuite {

    "Match issuer path" {
        val issuerIdentifier = "https://issuer.example.com/"
        val issuer = IssuerAgent(
            identifier = issuerIdentifier.toUri(),
            randomSource = RandomSource.Default
        )
        val holderKeyMaterial = EphemeralKeyWithoutCert()
        val holder = HolderAgent(
            keyMaterial = holderKeyMaterial,
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

        DCQLQueryAdapter(
            Json.decodeFromString<DCQLQuery>(
                """
                  {
                    "credential_sets": [
                      {
                        "options": [
                          ["pid_sd_jwt"]
                        ]
                      }
                    ],
                    "credentials": [
                      {
                        "id": "pid_sd_jwt",
                        "format": "dc+sd-jwt",
                        "meta": {
                          "vct_values": ["AtomicAttribute2023"]
                        },
                        "claims": [
                          {
                            "path": ["${ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME}"]
                          },
                          {
                            "path": ["iss"],
                            "values": ["$issuerIdentifier"]
                          }
                        ]
                      }
                    ]
                  }
                """.trimIndent()
            )
        ).select(
            credentials = listOf(credential)
        ).getOrThrow().credentialQueryMatches shouldHaveSize 1

        DCQLQueryAdapter(
            Json.decodeFromString<DCQLQuery>(
                """
                  {
                    "credential_sets": [
                      {
                        "options": [
                          ["pid_sd_jwt"]
                        ]
                      }
                    ],
                    "credentials": [
                      {
                        "id": "pid_sd_jwt",
                        "format": "dc+sd-jwt",
                        "meta": {
                          "vct_values": ["AtomicAttribute2023"]
                        },
                        "claims": [
                          {
                            "path": ["${ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME}"]
                          },
                          {
                            "path": ["iss"],
                            "values": ["${issuerIdentifier.reversed()}"]
                          }
                        ]
                      }
                    ]
                  }
                """.trimIndent()
            )
        ).select(
            credentials = listOf(credential)
        ).isFailure shouldBe true
    }

    "Match authority key identifier" {
        val aki = Random.nextBytes(20)
        val issuerKeyMaterial = EphemeralKeyWithSelfSignedCert(
            extensions = listOf(
                X509CertificateExtension(
                    oid = AuthorityKeyIdentifier.oid,
                    value = Asn1EncapsulatingOctetString(listOf(AuthorityKeyIdentifier(aki).encodeToTlv()))
                )
            )
        )
        val issuer = IssuerAgent(
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default,
            keyMaterial = issuerKeyMaterial
        )
        val holderKeyMaterial = EphemeralKeyWithoutCert()
        val holder = HolderAgent(
            keyMaterial = holderKeyMaterial,
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

        DCQLQueryAdapter(
            Json.decodeFromString<DCQLQuery>(
                """
                  {
                    "credential_sets": [
                      {
                        "options": [
                          ["pid_sd_jwt"]
                        ]
                      }
                    ],
                    "credentials": [
                      {
                        "id": "pid_sd_jwt",
                        "format": "dc+sd-jwt",
                        "meta": {
                          "vct_values": ["AtomicAttribute2023"]
                        },
                        "trusted_authorities": [
                          {
                            "type": "aki",
                            "values": ["${aki.encodeToString(Base64UrlStrict)}"]
                          }
                        ],
                        "claims": [
                          {
                            "path": ["${ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME}"]
                          }
                        ]
                      }
                    ]
                  }
                """.trimIndent()
            )
        ).select(
            credentials = listOf(credential)
        ).getOrThrow().credentialQueryMatches shouldHaveSize 1

        DCQLQueryAdapter(
            Json.decodeFromString<DCQLQuery>(
                """
                  {
                    "credential_sets": [
                      {
                        "options": [
                          ["pid_sd_jwt"]
                        ]
                      }
                    ],
                    "credentials": [
                      {
                        "id": "pid_sd_jwt",
                        "format": "dc+sd-jwt",
                        "meta": {
                          "vct_values": ["AtomicAttribute2023"]
                        },
                        "trusted_authorities": [
                          {
                            "type": "aki",
                            "values": ["${aki.encodeToString(Base64UrlStrict).reversed()}"]
                          }
                        ],
                        "claims": [
                          {
                            "path": ["${ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME}"]
                          }
                        ]
                      }
                    ]
                  }
                """.trimIndent()
            )
        ).select(
            credentials = listOf(credential)
        ).isFailure shouldBe true
    }
}
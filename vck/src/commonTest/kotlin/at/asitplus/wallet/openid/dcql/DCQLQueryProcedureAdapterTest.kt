package at.asitplus.wallet.openid.dcql

import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLQueryResponse
import at.asitplus.iso.DeviceAuth
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.DeviceSigned
import at.asitplus.iso.Document
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.issueIsoMdoc
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.issueSdJwt
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.ValidatorMdoc
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.procedures.dcql.AuthorityKeyIdentifier
import at.asitplus.wallet.lib.procedures.dcql.DCQLQueryAdapter
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json
import kotlin.random.Random

val DCQLQueryProcedureAdapterTest by matrixSuite {

    "Reject ISO submission when requested claim is not valid" {
        val issuer = IssuerAgent(
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default,
            keyMaterial = EphemeralKeyWithSelfSignedCert(),
        )
        val credential = issueIsoMdoc(issuer, EphemeralKeyWithoutCert())
            .shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()
        val parsedDocument = ValidatorMdoc().verifyDocument(
            Document(
                docType = ConstantIndex.AtomicAttribute2023.isoDocType,
                issuerSigned = credential.issuerSigned,
                deviceSigned = DeviceSigned(
                    namespaces = ByteStringWrapper(DeviceNameSpaces(mapOf())),
                    deviceAuth = DeviceAuth(),
                ),
            )
        ) { _, _ -> true }
        val requestedClaim = parsedDocument.validItems.first {
            it.elementIdentifier == ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
        }
        val presentation = Verifier.VerifyPresentationResult.SuccessIso(
            listOf(parsedDocument.copy(validItems = parsedDocument.validItems - requestedClaim))
        )
        val dcqlQuery = Json.decodeFromString<DCQLQuery>(
            """
              {
                "credentials": [
                  {
                    "id": "pid_mdoc",
                    "format": "mso_mdoc",
                    "meta": {
                      "doctype_value": "${ConstantIndex.AtomicAttribute2023.isoDocType}"
                    },
                    "claims": [
                      {
                        "path": [
                          "${ConstantIndex.AtomicAttribute2023.isoNamespace}",
                          "${ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME}"
                        ]
                      }
                    ]
                  }
                ]
              }
            """.trimIndent()
        )

        dcqlQuery.checkSubmissionRequirements(presentation).isFailure shouldBe true
    }

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
        val issuedCredential = issueSdJwt(issuer, holderKeyMaterial)
            .shouldBeInstanceOf<Issuer.IssuedCredential.VcSdJwt>()
        val credential = holder.storeCredential(issuedCredential.toStoreCredentialInput()).getOrThrow()
        val presentation = VerifierAgent("verifier").verifyPresentationSdJwt(
            input = issuedCredential.signedSdJwtVc,
            challenge = "",
            requireCryptographicHolderBinding = false,
        ).getOrThrow()

        val validQuery = Json.decodeFromString<DCQLQuery>(
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
        DCQLQueryAdapter(validQuery).select(
            credentials = listOf(credential)
        ).credentialQueryMatches shouldHaveSize 1
        validQuery.checkSubmissionRequirements(presentation).isSuccess shouldBe true

        val invalidQuery = Json.decodeFromString<DCQLQuery>(
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
        DCQLQueryAdapter(invalidQuery).select(
            credentials = listOf(credential)
        ).let {
            invalidQuery.checkCredentialSetQueryRequirements(it.credentialQueryMatches.filter {
                it.value.isNotEmpty()
            }.keys).isSuccess shouldBe false
        }
        invalidQuery.checkSubmissionRequirements(presentation).isFailure shouldBe true
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
        val issuedCredential = issueSdJwt(issuer, holderKeyMaterial)
            .shouldBeInstanceOf<Issuer.IssuedCredential.VcSdJwt>()
        val credential = holder.storeCredential(issuedCredential.toStoreCredentialInput()).getOrThrow()
        val presentation = VerifierAgent("verifier").verifyPresentationSdJwt(
            input = issuedCredential.signedSdJwtVc,
            challenge = "",
            requireCryptographicHolderBinding = false,
        ).getOrThrow()

        val validQuery = Json.decodeFromString<DCQLQuery>(
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
        DCQLQueryAdapter(validQuery).select(
            credentials = listOf(credential)
        ).credentialQueryMatches shouldHaveSize 1
        validQuery.checkSubmissionRequirements(presentation).isSuccess shouldBe true

        val invalidQuery = Json.decodeFromString<DCQLQuery>(
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
        DCQLQueryAdapter(invalidQuery).select(
            credentials = listOf(credential)
        ).let {
            invalidQuery.checkCredentialSetQueryRequirements(it.credentialQueryMatches.filter {
                it.value.isNotEmpty()
            }.keys).isSuccess shouldBe false
        }
        invalidQuery.checkSubmissionRequirements(presentation).isFailure shouldBe true
    }
}

private fun DCQLQuery.checkSubmissionRequirements(presentation: Verifier.VerifyPresentationResult) =
    DCQLQueryAdapter(this).checkSubmissionRequirements(
        DCQLQueryResponse(mapOf(credentials.single().id to listOf(presentation)))
    )

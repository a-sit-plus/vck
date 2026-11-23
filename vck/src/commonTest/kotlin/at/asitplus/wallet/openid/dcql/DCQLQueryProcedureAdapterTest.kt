package at.asitplus.wallet.openid.dcql

import at.asitplus.iso.DeviceAuth
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.DeviceSigned
import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.cosef.CoseSigned
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
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.integrityOnlyPolicy
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.procedures.dcql.AuthorityKeyIdentifier
import at.asitplus.wallet.lib.procedures.dcql.DCQLQueryAdapter
import at.asitplus.wallet.lib.validation.CredentialValidator
import at.asitplus.wallet.lib.validation.PresentationContext
import at.asitplus.wallet.lib.validation.PresentationValidationInput
import at.asitplus.wallet.lib.validation.ValidatedCredential
import at.asitplus.wallet.lib.validation.ValidatedPresentation
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.random.Random
import kotlinx.serialization.json.Json

val DCQLQueryProcedureAdapterTest by matrixSuite {

    "Reject ISO submission when requested claim is not valid" {
        val issuer = IssuerAgent(
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default,
            keyMaterial = EphemeralKeyWithSelfSignedCert(),
        )
        val credential = issueIsoMdoc(issuer, EphemeralKeyWithoutCert())
            .shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()
        // the document as accepted without the requested claim, i.e. the holder withheld it
        val issuerSigned = IssuerSigned.fromIssuerSignedItems(
            namespacedItems = credential.issuerSigned.namespaces.shouldNotBeNull().mapValues { namespace ->
                namespace.value.entries.map { it.value }
                    .filter { it.elementIdentifier != ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME }
            },
            issuerAuth = credential.issuerSigned.issuerAuth,
        )
        val presentation = ValidatedPresentation.MdocDocument(
            document = Document(
                docType = ConstantIndex.AtomicAttribute2023.isoDocType,
                issuerSigned = issuerSigned,
                deviceSigned = DeviceSigned(
                    namespaces = ByteStringWrapper(DeviceNameSpaces(mapOf())),
                    deviceAuth = DeviceAuth(),
                ),
            ),
            credential = ValidatedCredential.IsoMdoc(issuerSigned),
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

    "An SD-JWT whose claims can not be read matches no query, while the others still match" {
        val holderKeyMaterial = EphemeralKeyWithoutCert()
        val holder = HolderAgent(keyMaterial = holderKeyMaterial)
        val issuer = IssuerAgent(
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default,
        )
        val stored = holder.storeCredential(issueSdJwt(issuer, holderKeyMaterial).toStoreCredentialInput())
            .getOrThrow().shouldBeInstanceOf<SubjectCredentialStore.StoreEntry.SdJwt>()
        val unreadable = stored.copy(vcSerialized = "not-an-sd-jwt~")
        val queryWithoutClaims = Json.decodeFromString<DCQLQuery>(
            """
              {
                "credentials": [
                  {
                    "id": "any_sd_jwt",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["${stored.sdJwt.verifiableCredentialType}"] }
                  }
                ]
              }
            """.trimIndent()
        )

        val result = DCQLQueryAdapter(queryWithoutClaims).select(credentials = listOf(unreadable, stored))

        result.credentialMatchingResults.values.single().map { it.isSuccess } shouldBe listOf(false, true)
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
        val presentation = issuedCredential.presentWithoutHolderBinding()

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
        val presentation = issuedCredential.presentWithoutHolderBinding()

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

    "Match authority key identifier of an mdoc with its x5chain in the protected header" {
        val aki = Random.nextBytes(20)
        val issuer = IssuerAgent(
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default,
            keyMaterial = EphemeralKeyWithSelfSignedCert(
                extensions = listOf(
                    X509CertificateExtension(
                        oid = AuthorityKeyIdentifier.oid,
                        value = Asn1EncapsulatingOctetString(listOf(AuthorityKeyIdentifier(aki).encodeToTlv()))
                    )
                )
            ),
        )
        val issued = issueIsoMdoc(issuer, EphemeralKeyWithoutCert()).shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()
        val issuerAuth = issued.issuerSigned.issuerAuth
        // ISO/IEC DIS 18013-5:2026, 12.3.4: "An mdoc reader should support the presence of the x5chain element in the
        // protected header"; not signed again, as matching does not verify signatures, validation does
        val protectedChainIssuerAuth = CoseSigned.create(
            protectedHeader = issuerAuth.protectedHeader.copy(
                certificateChain = issuerAuth.unprotectedHeader.shouldNotBeNull().certificateChain.shouldNotBeNull()
            ),
            unprotectedHeader = issuerAuth.unprotectedHeader?.copy(certificateChain = null),
            payload = issuerAuth.payload,
            signature = issuerAuth.signature,
            payloadSerializer = MobileSecurityObject.serializer(),
        )
        val issuerSigned = IssuerSigned.fromIssuerSignedItems(
            namespacedItems = issued.issuerSigned.namespaces.shouldNotBeNull()
                .mapValues { namespace -> namespace.value.entries.map { it.value } },
            issuerAuth = protectedChainIssuerAuth,
        )
        val storeEntry = SubjectCredentialStore.StoreEntry.Iso(
            issuerSigned = issuerSigned,
            schemeIdentifier = ConstantIndex.AtomicAttribute2023.isoDocType,
        )
        val presentation = ValidatedPresentation.MdocDocument(
            document = Document(
                docType = ConstantIndex.AtomicAttribute2023.isoDocType,
                issuerSigned = issuerSigned,
                deviceSigned = DeviceSigned(
                    namespaces = ByteStringWrapper(DeviceNameSpaces(mapOf())),
                    deviceAuth = DeviceAuth(),
                ),
            ),
            credential = ValidatedCredential.IsoMdoc(issuerSigned),
        )
        fun mdocQuery(authorityKeyIdentifier: String) = Json.decodeFromString<DCQLQuery>(
            """
              {
                "credentials": [
                  {
                    "id": "mdoc",
                    "format": "mso_mdoc",
                    "meta": {
                      "doctype_value": "${ConstantIndex.AtomicAttribute2023.isoDocType}"
                    },
                    "trusted_authorities": [
                      {
                        "type": "aki",
                        "values": ["$authorityKeyIdentifier"]
                      }
                    ],
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
        val matchingQuery = mdocQuery(aki.encodeToString(Base64UrlStrict))
        val otherQuery = mdocQuery(aki.encodeToString(Base64UrlStrict).reversed())

        val walletMatches = DCQLQueryAdapter(matchingQuery).select(credentials = listOf(storeEntry))
        val walletMatchesOther = DCQLQueryAdapter(otherQuery).select(credentials = listOf(storeEntry))
        val verifierCheck = matchingQuery.checkSubmissionRequirements(presentation)
        val verifierCheckOther = otherQuery.checkSubmissionRequirements(presentation)

        walletMatches.credentialQueryMatches.values.single() shouldHaveSize 1
        walletMatchesOther.credentialQueryMatches.values.single() shouldHaveSize 0
        verifierCheck.isSuccess shouldBe true
        verifierCheckOther.isFailure shouldBe true
    }
}

private fun DCQLQuery.checkSubmissionRequirements(presentation: ValidatedPresentation) =
    DCQLQueryAdapter(this).checkAcceptedSubmissions(mapOf(credentials.single().id to listOf(presentation)))

/** The issued SD-JWT, presented without key binding JWT, as accepted by a verifier not requiring holder binding. */
private suspend fun Issuer.IssuedCredential.VcSdJwt.presentWithoutHolderBinding(): ValidatedPresentation =
    CredentialValidator().validate(
        input = PresentationValidationInput.SdJwt(signedSdJwtVc.serialize()),
        context = PresentationContext(challenge = "challenge", audience = "verifier", requireHolderBinding = false),
        policy = integrityOnlyPolicy,
    ).presentation.shouldNotBeNull()

package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import at.asitplus.testballoon.withDataSuites
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import kotlin.random.Random

val DCQLQueryTest by testSuite {
    "specification" - {
        "serial names" {
            DCQLQuery.SerialNames.CREDENTIALS shouldBe "credentials"
            DCQLQuery.SerialNames.CREDENTIAL_SETS shouldBe "credential_sets"
        }
    }
    "instance serialization" {
        val queryId1 = DCQLCredentialQueryIdentifier(
            Random.Default.nextBytes(32).encodeToString(Base64UrlStrict)
        )
        val serialized = Json.encodeToJsonElement(
            DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    DCQLIsoMdocCredentialQuery(
                        id = queryId1,
                        format = CredentialFormatEnum.MSO_MDOC,
                        meta = DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                            doctypeValue = "anything"
                        )
                    )
                ),
                credentialSets = nonEmptyListOf(
                    DCQLCredentialSetQuery(
                        options = nonEmptyListOf(listOf(queryId1))
                    )
                ),
            )
        ).jsonObject

        DCQLQuery.SerialNames.CREDENTIALS shouldBeIn serialized.keys
        DCQLQuery.SerialNames.CREDENTIAL_SETS shouldBeIn serialized.keys
    }
    "specification examples" - {
        "6.5" - {
            val dcqlQuery = """
            {
              "credentials": [
                {
                  "id": "my_credential",
                  "format": "dc+sd-jwt",
                  "meta": {
                    "vct_values": [ "https://credentials.example.com/identity_credential" ]
                  },
                  "claims": [
                      {"path": ["last_name"]},
                      {"path": ["first_name"]},
                      {"path": ["address", "street_address"]}
                  ]
                }
              ]
            }
        """.trimIndent().let {
                Json.decodeFromString<DCQLQuery>(it)
            }

            "failing" - {
                withData(
                     mapOf(
                        "empty database" to listOf<TestCredential>(),
                        "iso mdoc database" to listOf<TestCredential>(
                            TestCredential.MdocCredential(
                                documentType = uuid4().toString(),
                                namespaces = mapOf(),
                            ),
                            TestCredential.MdocCredential(
                                documentType = uuid4().toString(),
                                namespaces = mapOf(
                                    "last_name" to mapOf(
                                        "any" to "dummyStringValue"
                                    ),
                                    "first_name" to mapOf(
                                        "any" to "dummyStringValue"
                                    ),
                                    "address" to mapOf(
                                        "street_address" to "dummyStringValue"
                                    ),
                                ),
                            ),
                        ),
                        "sd jwt database with only partial matches" to listOf<TestCredential>(
                            TestCredential.SdJwtCredential(
                                type = "not the type in question",
                                claimStructure = buildJsonObject {
                                    put("last_name", "dummyStringValue")
                                    put("first_name", "dummyStringValue")
                                    put("address", buildJsonObject {
                                        put("street_address", "dummyStringValue")
                                    })
                                },
                            ),
                            TestCredential.SdJwtCredential(
                                type = "https://credentials.example.com/identity_credential",
                                claimStructure = buildJsonObject {
                                    put("last_name", "dummyStringValue")
                                    put("first_name", "dummyStringValue")
                                },
                            ),
                        ),
                    ),
                ) {
                    shouldThrowAny {
                        TestCredentialQueryAdapter(dcqlQuery).execute(it).getOrThrow()
                    }
                }
            }

            "success" - {
                withData(
                     mapOf(
                        "empty database" to listOf<TestCredential>(
                            TestCredential.SdJwtCredential(
                                type = "https://credentials.example.com/identity_credential",
                                claimStructure = buildJsonObject {
                                    put("last_name", "dummyStringValue")
                                    put("first_name", "dummyStringValue")
                                    put("address", buildJsonObject {
                                        put("street_address", "dummyStringValue")
                                    })
                                },
                            ),
                        ),
                        "with other mdoc credentials" to listOf<TestCredential>(
                            TestCredential.MdocCredential(
                                documentType = uuid4().toString(), namespaces = mapOf()
                            ),
                            TestCredential.MdocCredential(
                                documentType = uuid4().toString(), namespaces = mapOf(
                                    "last_name" to mapOf(
                                        "any" to "dummyStringValue"
                                    ),
                                    "first_name" to mapOf(
                                        "any" to "dummyStringValue"
                                    ),
                                    "address" to mapOf(
                                        "street_address" to "dummyStringValue"
                                    ),
                                )
                            ),
                            TestCredential.SdJwtCredential(type = "https://credentials.example.com/identity_credential",
                                claimStructure = buildJsonObject {
                                    put("last_name", "dummyStringValue")
                                    put("first_name", "dummyStringValue")
                                    put("address", buildJsonObject {
                                        put("street_address", "dummyStringValue")
                                    })
                                }),
                        ),
                        "with other credentials with only partial match" to listOf<TestCredential>(
                            TestCredential.SdJwtCredential(type = "not the type in question",
                                claimStructure = buildJsonObject {
                                    put("last_name", "dummyStringValue")
                                    put("first_name", "dummyStringValue")
                                    put("address", buildJsonObject {
                                        put("street_address", "dummyStringValue")
                                    })
                                }),
                            TestCredential.SdJwtCredential(type = "https://credentials.example.com/identity_credential",
                                claimStructure = buildJsonObject {
                                    put("last_name", "dummyStringValue")
                                    put("first_name", "dummyStringValue")
                                }),
                            TestCredential.SdJwtCredential(type = "https://credentials.example.com/identity_credential",
                                claimStructure = buildJsonObject {
                                    put("last_name", "dummyStringValue")
                                    put("first_name", "dummyStringValue")
                                    put("address", buildJsonObject {
                                        put("street_address", "dummyStringValue")
                                    })
                                }),
                        ),
                    )
                ) {
                    val result = TestCredentialQueryAdapter(dcqlQuery).execute(it).getOrThrow()
                    result.satisfiableCredentialSetQueries shouldHaveSize 1
                    result.credentialQueryMatches shouldHaveSize 1
                    result.credentialQueryMatches.values.first() shouldHaveSize 1
                }
            }
        }
        "Additional Examples 1 - credentials (iso)" - {
            val dcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "my_credential",
                      "format": "mso_mdoc",
                      "meta": {
                        "doctype_value": "org.iso.7367.1.mVRC"
                      },
                      "claims": [
                        {
                          "namespace": "org.iso.7367.1",
                          "claim_name": "vehicle_holder"
                        },
                        {
                          "namespace": "org.iso.18013.5.1",
                          "claim_name": "first_name"
                        }
                      ]
                    }
                  ]
                }
            """.trimIndent().let {
                Json.decodeFromString<DCQLQuery>(it)
            }

            "failing" - {
                withData(
                     mapOf(
                        "empty database" to listOf<TestCredential>(),
                        "iso mdoc database with only partial matches" to listOf<TestCredential>(
                            TestCredential.MdocCredential(
                                documentType = "org.iso.7367.1.mVRC",
                                namespaces = mapOf(
                                    "org.iso.7367.1" to mapOf(
                                        "vehicle_holder" to "dummyStringValue"
                                    ),
                                ),
                            ),
                            TestCredential.MdocCredential(
                                documentType = "org.iso.7367.1.mVRC",
                                namespaces = mapOf(
                                    "org.iso.18013.5.1" to mapOf(
                                        "first_name" to "dummyStringValue"
                                    )
                                ),
                            ),
                            TestCredential.MdocCredential(
                                documentType = "org.iso.7367.2.mVRC",
                                namespaces = mapOf(
                                    "org.iso.7367.1" to mapOf(
                                        "vehicle_holder" to "dummyStringValue"
                                    ),
                                    "org.iso.18013.5.1" to mapOf(
                                        "first_name" to "dummyStringValue"
                                    )
                                ),
                            ),
                        ),
                        "sd jwt database" to listOf<TestCredential>(
                            TestCredential.SdJwtCredential(
                                type = "org.iso.7367.1.mVRC",
                                claimStructure = buildJsonObject {
                                    put("org.iso.7367.1.mVRC", buildJsonObject {
                                        put("vehicle_holder", "dummyStringValue")
                                    })
                                    put("org.iso.18013.5.1", buildJsonObject {
                                        put("first_name", "dummyStringValue")
                                    })
                                },
                            ),
                        ),
                    ),
                ) {
                    shouldThrowAny {
                        TestCredentialQueryAdapter(dcqlQuery).execute(it).getOrThrow()
                    }
                }
            }

            "success" - {
                withData(
                   mapOf(
                        "empty database" to listOf<TestCredential>(
                            TestCredential.MdocCredential(
                                documentType = "org.iso.7367.1.mVRC",
                                namespaces = mapOf(
                                    "org.iso.18013.5.1" to mapOf(
                                        "first_name" to "dummyStringValue"
                                    ),
                                    "org.iso.7367.1" to mapOf(
                                        "vehicle_holder" to "dummyStringValue"
                                    )
                                ),
                            ),
                        ),
                        "iso mdoc database with only partial matches" to listOf<TestCredential>(
                            TestCredential.MdocCredential(
                                documentType = "org.iso.7367.1.mVRC",
                                namespaces = mapOf(
                                    "org.iso.7367.1" to mapOf(
                                        "vehicle_holder" to "dummyStringValue"
                                    ),
                                ),
                            ),
                            TestCredential.MdocCredential(
                                documentType = "org.iso.7367.1.mVRC",
                                namespaces = mapOf(
                                    "org.iso.18013.5.1" to mapOf(
                                        "first_name" to "dummyStringValue"
                                    )
                                ),
                            ),
                            TestCredential.MdocCredential(
                                documentType = "org.iso.7367.1.mVRC",
                                namespaces = mapOf(
                                    "org.iso.18013.5.1" to mapOf(
                                        "first_name" to "dummyStringValue"
                                    ),
                                    "org.iso.7367.1" to mapOf(
                                        "vehicle_holder" to "dummyStringValue"
                                    )
                                ),
                            ),
                        ),
                        "sd jwt database" to listOf<TestCredential>(
                            TestCredential.SdJwtCredential(
                                type = "org.iso.7367.1.mVRC",
                                claimStructure = buildJsonObject {
                                    put("org.iso.7367.1.mVRC", buildJsonObject {
                                        put("vehicle_holder", "dummyStringValue")
                                    })
                                    put("org.iso.18013.5.1", buildJsonObject {
                                        put("first_name", "dummyStringValue")
                                    })
                                },
                            ),
                            TestCredential.MdocCredential(
                                documentType = "org.iso.7367.1.mVRC",
                                namespaces = mapOf(
                                    "org.iso.18013.5.1" to mapOf(
                                        "first_name" to "dummyStringValue"
                                    ),
                                    "org.iso.7367.1" to mapOf(
                                        "vehicle_holder" to "dummyStringValue"
                                    )
                                ),
                            ),
                        ),
                    )
                ) {
                    val result = TestCredentialQueryAdapter(dcqlQuery).execute(it).getOrThrow()
                    result.satisfiableCredentialSetQueries shouldHaveSize 1
                    result.credentialQueryMatches shouldHaveSize 1
                    result.credentialQueryMatches.values.first() shouldHaveSize 1
                }
            }
        }

        "Additional Examples 2 - credentials (sd jwt)" - {
            val dcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "dc+sd-jwt",
                      "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                      },
                      "claims": [
                        {"path": ["given_name"]},
                        {"path": ["family_name"]},
                        {"path": ["address", "street_address"]}
                      ]
                    },
                    {
                      "id": "mdl",
                      "format": "mso_mdoc",
                      "meta": {
                        "doctype_value": "org.iso.7367.1.mVRC"
                      },
                      "claims": [
                        {
                          "namespace": "org.iso.7367.1",
                          "claim_name": "vehicle_holder"
                        },
                        {
                          "namespace": "org.iso.18013.5.1",
                          "claim_name": "first_name"
                        }
                      ]
                    }
                ]
                }
            """.trimIndent().trimIndent().let {
                Json.decodeFromString<DCQLQuery>(it)
            }

            "failing" - {
                withData(
                   mapOf(
                        "empty database" to listOf<TestCredential>(),
                        "database with only one matching credential 1" to listOf<TestCredential>(
                            TestCredential.MdocCredential(
                                documentType = "org.iso.7367.1.mVRC",
                                namespaces = mapOf(
                                    "org.iso.18013.5.1" to mapOf(
                                        "first_name" to "dummyStringValue"
                                    ),
                                    "org.iso.7367.1" to mapOf(
                                        "vehicle_holder" to "dummyStringValue"
                                    )
                                ),
                            ),
                        ),
                        "database with only one matching credential 2" to listOf<TestCredential>(
                            TestCredential.SdJwtCredential(
                                type = "https://credentials.example.com/identity_credential",
                                claimStructure = buildJsonObject {
                                    put("family_name", "dummyStringValue")
                                    put("given_name", "dummyStringValue")
                                    put("address", buildJsonObject {
                                        put("street_address", "dummyStringValue")
                                    })
                                },
                            ),
                        ),
                    ),
                ) {
                    shouldThrowAny {
                        TestCredentialQueryAdapter(dcqlQuery).execute(it).getOrThrow()
                    }
                }
            }

            "success" - {
                withData(
                   mapOf(
                        "database with both matching credentials" to listOf<TestCredential>(
                            TestCredential.MdocCredential(
                                documentType = "org.iso.7367.1.mVRC",
                                namespaces = mapOf(
                                    "org.iso.18013.5.1" to mapOf(
                                        "first_name" to "dummyStringValue"
                                    ),
                                    "org.iso.7367.1" to mapOf(
                                        "vehicle_holder" to "dummyStringValue"
                                    )
                                ),
                            ),
                            TestCredential.SdJwtCredential(
                                type = "https://credentials.example.com/identity_credential",
                                claimStructure = buildJsonObject {
                                    put("family_name", "dummyStringValue")
                                    put("given_name", "dummyStringValue")
                                    put("address", buildJsonObject {
                                        put("street_address", "dummyStringValue")
                                    })
                                },
                            ),
                        ),
                    )
                ) {
                    val result = TestCredentialQueryAdapter(dcqlQuery).execute(it).getOrThrow()
                    result.satisfiableCredentialSetQueries shouldHaveSize 1
                    result.credentialQueryMatches shouldHaveSize 2
                    result.credentialQueryMatches.values.first() shouldHaveSize 1
                }
            }
        }

        "Additional Examples 3 - credential set queries (sd jwt)" - {
            val dcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "dc+sd-jwt",
                      "meta": {
                        "vct_values": ["https://credentials.example.com/identity_credential"]
                      },
                      "claims": [
                        {"path": ["given_name"]},
                        {"path": ["family_name"]},
                        {"path": ["address", "street_address"]}
                      ]
                    },
                    {
                      "id": "other_pid",
                      "format": "dc+sd-jwt",
                      "meta": {
                        "vct_values": ["https://othercredentials.example/pid"]
                      },
                      "claims": [
                        {"path": ["given_name"]},
                        {"path": ["family_name"]},
                        {"path": ["address", "street_address"]}
                      ]
                    },
                    {
                      "id": "pid_reduced_cred_1",
                      "format": "dc+sd-jwt",
                      "meta": {
                        "vct_values": ["https://credentials.example.com/reduced_identity_credential"]
                      },
                      "claims": [
                        {"path": ["family_name"]},
                        {"path": ["given_name"]}
                      ]
                    },
                    {
                      "id": "pid_reduced_cred_2",
                      "format": "dc+sd-jwt",
                      "meta": {
                        "vct_values": ["https://cred.example/residence_credential"]
                      },
                      "claims": [
                        {"path": ["postal_code"]},
                        {"path": ["locality"]},
                        {"path": ["region"]}
                      ]
                    },
                    {
                      "id": "nice_to_have",
                      "format": "dc+sd-jwt",
                      "meta": {
                        "vct_values": ["https://company.example/company_rewards"]
                      },
                      "claims": [
                        {"path": ["rewards_number"]}
                      ]
                    }
                  ],
                  "credential_sets": [
                    {
                      "options": [
                        [ "pid" ],
                        [ "other_pid" ],
                        [ "pid_reduced_cred_1", "pid_reduced_cred_2" ]
                      ]
                    },
                    {
                      "required": false,
                      "options": [
                        [ "nice_to_have" ]
                      ]
                    }
                  ]
                }
            """.trimIndent().trimIndent().let {
                Json.decodeFromString<DCQLQuery>(it)
            }

            val pidCredential = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/identity_credential",
                claimStructure = buildJsonObject {
                    put("given_name", "dummyStringValue")
                    put("family_name", "dummyStringValue")
                    put("address", buildJsonObject {
                        put("street_address", "dummyStringValue")
                    })
                }
            )
            val otherPidCredential = TestCredential.SdJwtCredential(
                type = "https://othercredentials.example/pid",
                claimStructure = buildJsonObject {
                    put("given_name", "dummyStringValue")
                    put("family_name", "dummyStringValue")
                    put("address", buildJsonObject {
                        put("street_address", "dummyStringValue")
                    })
                }
            )
            val reducedCred1 = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/reduced_identity_credential",
                claimStructure = buildJsonObject {
                    put("given_name", "dummyStringValue")
                    put("family_name", "dummyStringValue")
                }
            )
            val reducedCred2 = TestCredential.SdJwtCredential(
                type = "https://cred.example/residence_credential",
                claimStructure = buildJsonObject {
                    put("postal_code", "dummyStringValue")
                    put("locality", "dummyStringValue")
                    put("region", "dummyStringValue")
                }
            )
            val niceToHaveCredential = TestCredential.SdJwtCredential(
                type = "https://company.example/company_rewards",
                claimStructure = buildJsonObject {
                    put("rewards_number", "dummyStringValue")
                }
            )

            "failing" - {
                withData(
                   mapOf(
                        "empty database" to listOf<TestCredential>(),
                        "database without reduced 2" to listOf(
                            reducedCred1,
                        ),
                        "database without reduced 1" to listOf(
                            reducedCred2,
                        ),
                        "database without reduced 2 but optionals" to listOf(
                            reducedCred1,
                            niceToHaveCredential,
                        ),
                        "database without reduced 1 but optionals" to listOf(
                            reducedCred2,
                            niceToHaveCredential,
                        ),
                    ),
                ) {
                    shouldThrowAny {
                        TestCredentialQueryAdapter(dcqlQuery).execute(it).getOrThrow()
                    }
                }
            }

            "success" - {
                withData(
                   mapOf(
                        "database with pid" to listOf(
                            pidCredential,
                        ),
                        "database with other pid" to listOf(
                            otherPidCredential,
                        ),
                        "reduced creds" to listOf(
                            reducedCred1,
                            reducedCred2,
                        ),
                        "database with any required" to listOf(
                            pidCredential,
                            otherPidCredential,
                            reducedCred1,
                            reducedCred2,
                        ),
                        "database with any all" to listOf(
                            pidCredential,
                            otherPidCredential,
                            reducedCred1,
                            reducedCred2,
                            niceToHaveCredential,
                        ),
                    )
                ) {
                    TestCredentialQueryAdapter(dcqlQuery).execute(it).getOrThrow()
                }
            }
        }

        "Additional Examples 4 - credential set queries (iso)" - {
            val dcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "mdl-id",
                      "format": "mso_mdoc",
                      "meta": {
                        "doctype_value": "org.iso.18013.5.1.mDL"
                      },
                      "claims": [
                        {
                          "id": "given_name",
                          "namespace": "org.iso.18013.5.1",
                          "claim_name": "given_name"
                        },
                        {
                          "id": "family_name",
                          "namespace": "org.iso.18013.5.1",
                          "claim_name": "family_name"
                        },
                        {
                          "id": "portrait",
                          "namespace": "org.iso.18013.5.1",
                          "claim_name": "portrait"
                        }
                      ]
                    },
                    {
                      "id": "mdl-address",
                      "format": "mso_mdoc",
                      "meta": {
                        "doctype_value": "org.iso.18013.5.1.mDL"
                      },
                      "claims": [
                        {
                          "id": "resident_address",
                          "namespace": "org.iso.18013.5.1",
                          "claim_name": "resident_address"
                        },
                        {
                          "id": "resident_country",
                          "namespace": "org.iso.18013.5.1",
                          "claim_name": "resident_country"
                        }
                      ]
                    },
                    {
                      "id": "photo_card-id",
                      "format": "mso_mdoc",
                      "meta": {
                        "doctype_value": "org.iso.23220.photoid.1"
                      },
                      "claims": [
                        {
                          "id": "given_name",
                          "namespace": "org.iso.23220.1",
                          "claim_name": "given_name"
                        },
                        {
                          "id": "family_name",
                          "namespace": "org.iso.23220.1",
                          "claim_name": "family_name"
                        },
                        {
                          "id": "portrait",
                          "namespace": "org.iso.23220.1",
                          "claim_name": "portrait"
                        }
                      ]
                    },
                    {
                      "id": "photo_card-address",
                      "format": "mso_mdoc",
                      "meta": {
                        "doctype_value": "org.iso.23220.photoid.1"
                      },
                      "claims": [
                        {
                          "id": "resident_address",
                          "namespace": "org.iso.23220.1",
                          "claim_name": "resident_address"
                        },
                        {
                          "id": "resident_country",
                          "namespace": "org.iso.23220.1",
                          "claim_name": "resident_country"
                        }
                      ]
                    }
                  ],
                  "credential_sets": [
                    {
                      "options": [
                        [ "mdl-id" ],
                        [ "photo_card-id" ]
                      ]
                    },
                    {
                      "required": false,
                      "options": [
                        [ "mdl-address" ],
                        [ "photo_card-address" ]
                      ]
                    }
                  ]
                }
            """.trimIndent().trimIndent().let {
                Json.decodeFromString<DCQLQuery>(it)
            }

            val mdlIdCred = TestCredential.MdocCredential(
                documentType = "org.iso.18013.5.1.mDL",
                namespaces = mapOf(
                    "org.iso.18013.5.1" to mapOf(
                        "given_name" to "dummyStringValue",
                        "family_name" to "dummyStringValue",
                        "portrait" to "dummyStringValue",
                    ),
                )
            )
            val mdlAddressCred = TestCredential.MdocCredential(
                documentType = "org.iso.18013.5.1.mDL",
                namespaces = mapOf(
                    "org.iso.18013.5.1" to mapOf(
                        "resident_address" to "dummyStringValue",
                        "resident_country" to "dummyStringValue",
                    ),
                )
            )
            val mdlFullCred = TestCredential.MdocCredential(
                documentType = "org.iso.18013.5.1.mDL",
                namespaces = mapOf(
                    "org.iso.18013.5.1" to mapOf(
                        "resident_address" to "dummyStringValue",
                        "resident_country" to "dummyStringValue",
                        "given_name" to "dummyStringValue",
                        "family_name" to "dummyStringValue",
                        "portrait" to "dummyStringValue",
                    ),
                )
            )
            val photoCardId = TestCredential.MdocCredential(
                documentType = "org.iso.23220.photoid.1",
                namespaces = mapOf(
                    "org.iso.23220.1" to mapOf(
                        "given_name" to "dummyStringValue",
                        "family_name" to "dummyStringValue",
                        "portrait" to "dummyStringValue",
                    ),
                )
            )
            val photoCardAddress = TestCredential.MdocCredential(
                documentType = "org.iso.23220.photoid.1",
                namespaces = mapOf(
                    "org.iso.23220.1" to mapOf(
                        "resident_address" to "dummyStringValue",
                        "resident_country" to "dummyStringValue",
                    ),
                )
            )
            val photoCardFull = TestCredential.MdocCredential(
                documentType = "org.iso.23220.photoid.1",
                namespaces = mapOf(
                    "org.iso.23220.1" to mapOf(
                        "given_name" to "dummyStringValue",
                        "family_name" to "dummyStringValue",
                        "portrait" to "dummyStringValue",
                        "resident_address" to "dummyStringValue",
                        "resident_country" to "dummyStringValue",
                    ),
                )
            )

            "failing" - {
                withData(
                   mapOf(
                        "empty database" to listOf<TestCredential>(),
                        "only addresses" to listOf(
                            mdlAddressCred,
                            photoCardAddress,
                        ),
                    ),
                ) {
                    shouldThrowAny {
                        TestCredentialQueryAdapter(dcqlQuery).execute(it).getOrThrow()
                    }
                }
            }

            "success" - {
                withData(
                   mapOf(
                        "database with mdl id" to listOf(
                            mdlIdCred
                        ),
                        "database with full mdl" to listOf(
                            mdlFullCred
                        ),
                        "database with multiple mdl" to listOf(
                            mdlIdCred,
                            mdlFullCred,
                        ),
                        "database with photoid" to listOf(
                            photoCardId
                        ),
                        "database with photoid full" to listOf(
                            photoCardFull
                        ),
                        "database with multiple photoid" to listOf(
                            photoCardId,
                            photoCardFull,
                        ),
                        "database with all id" to listOf(
                            photoCardId,
                            photoCardFull,
                            mdlIdCred,
                            mdlFullCred,
                        ),
                        "database with mdl id and optionals" to listOf(
                            mdlIdCred,
                            mdlAddressCred,
                            photoCardAddress,
                        ),
                        "database with full mdl and optionals" to listOf(
                            mdlFullCred,
                            mdlAddressCred,
                            photoCardAddress,
                        ),
                        "database with multiple mdl and optionals" to listOf(
                            mdlIdCred,
                            mdlFullCred,
                            mdlAddressCred,
                            photoCardAddress,
                        ),
                        "database with photoid and optionals" to listOf(
                            photoCardId,
                            mdlAddressCred,
                            photoCardAddress,
                        ),
                        "database with photoid full and optionals" to listOf(
                            photoCardFull,
                            mdlAddressCred,
                            photoCardAddress,
                        ),
                        "database with multiple photoid and optionals" to listOf(
                            photoCardId,
                            photoCardFull,
                            mdlAddressCred,
                            photoCardAddress,
                        ),
                        "database with all id and optionals" to listOf(
                            photoCardId,
                            photoCardFull,
                            mdlIdCred,
                            mdlFullCred,
                            mdlAddressCred,
                            photoCardAddress,
                        ),
                    )
                ) {
                    TestCredentialQueryAdapter(dcqlQuery).execute(it).getOrThrow()
                }
            }
        }

        "Additional Examples 5 - claims sets (sd jwt)" - {
            val dcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "pid",
                      "format": "dc+sd-jwt",
                      "meta": {
                        "vct_values": [ "https://credentials.example.com/identity_credential" ]
                      },
                      "claims": [
                        {"id": "a", "path": ["last_name"]},
                        {"id": "b", "path": ["postal_code"]},
                        {"id": "c", "path": ["locality"]},
                        {"id": "d", "path": ["region"]},
                        {"id": "e", "path": ["date_of_birth"]}
                      ],
                      "claim_sets": [
                        ["a", "c", "d", "e"],
                        ["a", "b", "e"]
                      ]
                    }
                  ]
                }
            """.trimIndent().trimIndent().let {
                Json.decodeFromString<DCQLQuery>(it)
            }

            val abcdeCred = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/identity_credential",
                claimStructure = buildJsonObject {
                    put("last_name", "dummyStringValue")
                    put("postal_code", "dummyStringValue")
                    put("locality", "dummyStringValue")
                    put("region", "dummyStringValue")
                    put("date_of_birth", "dummyStringValue")
                },
            )
            val acdeCred = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/identity_credential",
                claimStructure = buildJsonObject {
                    put("last_name", "dummyStringValue")
                    put("locality", "dummyStringValue")
                    put("region", "dummyStringValue")
                    put("date_of_birth", "dummyStringValue")
                },
            )
            val abeCred = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/identity_credential",
                claimStructure = buildJsonObject {
                    put("last_name", "dummyStringValue")
                    put("postal_code", "dummyStringValue")
                    put("date_of_birth", "dummyStringValue")
                },
            )
            val abCred = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/identity_credential",
                claimStructure = buildJsonObject {
                    put("last_name", "dummyStringValue")
                    put("postal_code", "dummyStringValue")
                },
            )
            val aeCred = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/identity_credential",
                claimStructure = buildJsonObject {
                    put("last_name", "dummyStringValue")
                    put("date_of_birth", "dummyStringValue")
                },
            )
            val beCred = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/identity_credential",
                claimStructure = buildJsonObject {
                    put("postal_code", "dummyStringValue")
                    put("date_of_birth", "dummyStringValue")
                },
            )
            val cdeCred = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/identity_credential",
                claimStructure = buildJsonObject {
                    put("locality", "dummyStringValue")
                    put("region", "dummyStringValue")
                    put("date_of_birth", "dummyStringValue")
                },
            )
            val adeCred = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/identity_credential",
                claimStructure = buildJsonObject {
                    put("last_name", "dummyStringValue")
                    put("region", "dummyStringValue")
                    put("date_of_birth", "dummyStringValue")
                },
            )
            val aceCred = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/identity_credential",
                claimStructure = buildJsonObject {
                    put("last_name", "dummyStringValue")
                    put("locality", "dummyStringValue")
                    put("date_of_birth", "dummyStringValue")
                },
            )
            val acdCred = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/identity_credential",
                claimStructure = buildJsonObject {
                    put("last_name", "dummyStringValue")
                    put("locality", "dummyStringValue")
                    put("region", "dummyStringValue")
                },
            )

            "failing" - {
                withData(
                   mapOf(
                        "empty database" to listOf<TestCredential>(),
                        "missing claims" to listOf(
                            acdCred,
                            aceCred,
                            adeCred,
                            cdeCred,
                            beCred,
                            aeCred,
                            abCred,
                        ),
                    ),
                ) {
                    shouldThrowAny {
                        TestCredentialQueryAdapter(dcqlQuery).execute(it).getOrThrow()
                    }
                }
            }

            "success" - {
                withData(
                   mapOf(
                        "abeCred" to listOf(
                            abeCred
                        ),
                        "acdeCred" to listOf(
                            acdeCred
                        ),
                        "acdeCred" to listOf(
                            abcdeCred
                        ),
                        "abeCreds" to listOf(
                            abeCred,
                            abcdeCred,
                        ),
                        "acdeCreds" to listOf(
                            abcdeCred,
                            abcdeCred,
                        ),
                    )
                ) {
                    TestCredentialQueryAdapter(dcqlQuery).execute(it).getOrThrow()
                }
            }
        }

        "Additional Examples 6 - values" - {
            val dcqlQuery = """
                {
                  "credentials": [
                    {
                      "id": "my_credential",
                      "format": "dc+sd-jwt",
                      "meta": {
                        "vct_values": [ "https://credentials.example.com/identity_credential" ]
                      },
                      "claims": [
                          {
                            "path": ["last_name"],
                            "values": ["Doe"]
                          },
                          {"path": ["first_name"]},
                          {"path": ["address", "street_address"]},
                          {
                            "path": ["postal_code"],
                            "values": ["90210", "90211"]
                          }
                      ]
                    }
                  ]
                }
            """.trimIndent().trimIndent().let {
                Json.decodeFromString<DCQLQuery>(it)
            }

            val valid1 = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/identity_credential",
                claimStructure = buildJsonObject {
                    put("last_name", "Doe")
                    put("first_name", "dummyStringValue")
                    put("address", buildJsonObject {
                        put("street_address", "dummyStringValue")
                    })
                    put("postal_code", "90210")
                },
            )
            val valid2 = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/identity_credential",
                claimStructure = buildJsonObject {
                    put("last_name", "Doe")
                    put("first_name", "dummyStringValue")
                    put("address", buildJsonObject {
                        put("street_address", "dummyStringValue")
                    })
                    put("postal_code", "90211")
                },
            )
            val wrongPostalCode = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/identity_credential",
                claimStructure = buildJsonObject {
                    put("last_name", "Doe")
                    put("first_name", "dummyStringValue")
                    put("address", buildJsonObject {
                        put("street_address", "dummyStringValue")
                    })
                    put("postal_code", "90212")
                },
            )
            val wrongPostalCodeType = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/identity_credential",
                claimStructure = buildJsonObject {
                    put("last_name", "Doe")
                    put("first_name", "dummyStringValue")
                    put("address", buildJsonObject {
                        put("street_address", "dummyStringValue")
                    })
                    put("postal_code", 90211)
                },
            )
            val wrongPostalCodeTypeAndValue = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/identity_credential",
                claimStructure = buildJsonObject {
                    put("last_name", "Doe")
                    put("first_name", "dummyStringValue")
                    put("address", buildJsonObject {
                        put("street_address", "dummyStringValue")
                    })
                    put("postal_code", true)
                },
            )
            val wrongName = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/identity_credential",
                claimStructure = buildJsonObject {
                    put("last_name", "Doee")
                    put("first_name", "dummyStringValue")
                    put("address", buildJsonObject {
                        put("street_address", "dummyStringValue")
                    })
                    put("postal_code", "90211")
                },
            )
            val missingFirstName = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/identity_credential",
                claimStructure = buildJsonObject {
                    put("last_name", "Doe")
                    put("address", buildJsonObject {
                        put("street_address", "dummyStringValue")
                    })
                    put("postal_code", "90211")
                },
            )
            val missingStreetAddress = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/identity_credential",
                claimStructure = buildJsonObject {
                    put("last_name", "Doe")
                    put("first_name", "dummyStringValue")
                    put("address", buildJsonObject {
                        put("street_address2", "dummyStringValue")
                    })
                    put("postal_code", "90211")
                },
            )
            val missingAddress = TestCredential.SdJwtCredential(
                type = "https://credentials.example.com/identity_credential",
                claimStructure = buildJsonObject {
                    put("last_name", "Doe")
                    put("first_name", "dummyStringValue")
                    put("postal_code", "90211")
                },
            )

            "failing" - {
                withData(
                   mapOf(
                        "empty database" to listOf<TestCredential>(),
                        "missing claims" to listOf(
                            missingAddress,
                            missingStreetAddress,
                            missingFirstName,
                            wrongName,
                            wrongPostalCode,
                            wrongPostalCodeType,
                            wrongPostalCodeTypeAndValue,
                        ),
                    ),
                ) {
                    shouldThrowAny {
                        TestCredentialQueryAdapter(dcqlQuery).execute(it).getOrThrow()
                    }
                }
            }

            "success" - {
                withData(
                   mapOf(
                        "valid1" to listOf(valid1),
                        "valid2" to listOf(valid2),
                    )
                ) {
                    TestCredentialQueryAdapter(dcqlQuery).execute(it).getOrThrow()
                }
            }
        }
    }
    "Manual written examples" - {
        "values" - {
            withDataSuites(
               mapOf(
                    // expected values json array, list of valid values, list of invalid values
                    "strings1" to Triple<String, List<Any?>, List<Any?>>(
                        """["expectedStringValue1", "2"]""",
                        listOf(
                            "expectedStringValue1",
                            "2",
                        ),
                        listOf(
                            null,
                            "unexpectedStringValue",
                            0,
                            2,
                            true,
                            false,
                        ),
                    ),
                    "integers1" to Triple<String, List<Any?>, List<Any?>>(
                        """[-1, 0, 1]""",
                        listOf(
                            0,
                            1,
                            -1,
                        ),
                        listOf(
                            null,
                            "0",
                            "1",
                            "-1",
                            -2,
                            2,
                            false,
                            true,
                            "unexpected string value",
                            "false",
                            "true",
                        ),
                    ),
                    "booleans1" to Triple<String, List<Any?>, List<Any?>>(
                        """[true, true]""",
                        listOf(
                            true
                        ),
                        listOf(
                            null,
                            "0",
                            "1",
                            0,
                            1,
                            false,
                            "false",
                            "true",
                        ),
                    )
                ),
            ) { testVector ->
                val sdJwtDcqlQuery = """ 
                    {
                      "credentials": [
                        {
                          "id": "my_credential",
                          "format": "${CredentialFormatEnum.DC_SD_JWT.text}",
                          "claims": [
                              {
                                "path": ["value"],
                                "values": ${testVector.first}
                              }
                          ],
                          "meta": {
                              "vct_values": [ "my_credential" ]
                          }
                        }
                      ]
                    }
                """.trimIndent().trimIndent().let {
                    Json.decodeFromString<DCQLQuery>(it)
                }
                val buildSdJwtValueCredential: (Any?) -> TestCredential.SdJwtCredential = {
                    TestCredential.SdJwtCredential(
                        type = "my_credential",
                        claimStructure = buildJsonObject {
                            if (it != null) {
                                put(
                                    "value", when (it) {
                                        is Int -> JsonPrimitive(it)
                                        is Boolean -> JsonPrimitive(it)
                                        is String -> JsonPrimitive(it)
                                        else -> JsonNull
                                    }
                                )
                            }
                        }
                    )
                }

                val mdocDcqlQuery = """
                    {
                      "credentials": [
                        {
                          "id": "my_credential",
                          "format": "${CredentialFormatEnum.MSO_MDOC.text}",
                          "claims": [
                              {
                                "${DCQLIsoMdocClaimsQuery.SerialNames.NAMESPACE}": "namespace",
                                "${DCQLIsoMdocClaimsQuery.SerialNames.CLAIM_NAME}": "claimName",
                                "${DCQLClaimsQuery.SerialNames.VALUES}": ${testVector.first}
                              }
                          ],
                          "meta": {
                              "doctype_value": "mDL"
                          }
                        }
                      ]
                    }
                """.trimIndent().trimIndent().let {
                    Json.decodeFromString<DCQLQuery>(it)
                }
                val buildMdocValueCredential: (Any?) -> TestCredential.MdocCredential = { value ->
                    TestCredential.MdocCredential(
                        documentType = "mDL",
                        namespaces = mapOf(
                            "namespace" to run {
                                if (value != null) {
                                    mapOf("claimName" to value)
                                } else {
                                    mapOf()
                                }
                            }
                        )
                    )
                }

                withData(testVector.second) {
                    val test = buildSdJwtValueCredential(it)
                    shouldNotThrowAny {
                        TestCredentialQueryAdapter(sdJwtDcqlQuery).execute(
                            listOf(test)
                        ).getOrThrow()
                    }
                }
                withData(testVector.second) {
                    shouldNotThrowAny {
                        TestCredentialQueryAdapter(mdocDcqlQuery).execute(
                            listOf(buildMdocValueCredential(it))
                        ).getOrThrow()
                    }
                }
                withData(testVector.third) {
                    shouldThrowAny {
                        TestCredentialQueryAdapter(sdJwtDcqlQuery).execute(
                            listOf(buildSdJwtValueCredential(it))
                        ).getOrThrow()
                    }
                }
                withData(testVector.third) {
                    shouldThrowAny {
                        TestCredentialQueryAdapter(mdocDcqlQuery).execute(
                            listOf(buildMdocValueCredential(it))
                        ).getOrThrow()
                    }
                }
            }
        }
    }
}
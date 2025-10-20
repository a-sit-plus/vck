package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import io.kotest.assertions.fail
import at.asitplus.testballoon.*
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

class OpenId4VpCombinedProtocolTest by testSuite{

    lateinit var clientId: String
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var holderOid4vp: OpenId4VpHolder
    lateinit var verifierOid4vp: OpenId4VpVerifier

    beforeEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithoutCert()
        clientId = "https://example.com/rp/${uuid4()}"
        holderAgent = HolderAgent(holderKeyMaterial)

        holderOid4vp = OpenId4VpHolder(
            keyMaterial = holderKeyMaterial,
            holder = holderAgent,
            randomSource = RandomSource.Default,
        )
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId),
        )
    }

    "support for format holder specification" - {
        "support for plain jwt credential request" - {
            "if not available despite others with correct format or correct attribute, but not both" {
                holderAgent.storeJwtCredential(holderKeyMaterial, MobileDrivingLicenceScheme)
                holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

                val authnRequest = verifierOid4vp.createAuthnRequest(
                    requestOptions = RequestOptions(
                        credentials = setOf(
                            RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
                        )
                    )
                )
                holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                    .error.shouldNotBeNull()
            }
            "if available despite others" {
                holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeJwtCredential(holderKeyMaterial, MobileDrivingLicenceScheme)
                holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

                val authnRequest = verifierOid4vp.createAuthnRequest(
                    requestOptions = RequestOptions(
                        credentials = setOf(
                            RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
                        )
                    )
                )

                val authnResponse =
                    holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                        .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

                verifierOid4vp.validateAuthnResponse(authnResponse.url)
                    .shouldBeInstanceOf<AuthnResponseResult.Success>()
                    .vp.freshVerifiableCredentials.shouldNotBeEmpty()
                    .map { it.vcJws }.forEach {
                        it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
                    }
            }
        }

        "support for sd jwt credential request" - {
            "when using presentation exchange" - {
                "if not available despite others with correct format or correct attribute, but not both" {
                    holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeSdJwtCredential(holderKeyMaterial, MobileDrivingLicenceScheme)
                    holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

                    val authnRequest = verifierOid4vp.createAuthnRequest(
                        requestOptions = RequestOptions(
                            credentials = setOf(
                                RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, SD_JWT)
                            )
                        )
                    )
                    holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                        .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                        .error.shouldNotBeNull()
                }

                "if available despite others with correct format or correct attribute, but not both" {
                    holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeSdJwtCredential(holderKeyMaterial, MobileDrivingLicenceScheme)
                    holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

                    val authnRequest = verifierOid4vp.createAuthnRequest(
                        requestOptions = RequestOptions(
                            credentials = setOf(
                                RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, SD_JWT)
                            )
                        ),
                    )
                    val authnResponse = holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                        .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

                    verifierOid4vp.validateAuthnResponse(authnResponse.url)
                        .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
                        .verifiableCredentialSdJwt.verifiableCredentialType shouldBe ConstantIndex.AtomicAttribute2023.sdJwtType
                }
            }
            "when using dcql" - {
                "if not available despite others with correct format or correct attribute, but not both" {
                    holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeSdJwtCredential(holderKeyMaterial, MobileDrivingLicenceScheme)
                    holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

                    val authnRequest = verifierOid4vp.prepareAuthnRequest(
                        requestOptions = RequestOptions(
                            credentials = setOf(
                                RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, SD_JWT)
                            ),
                            presentationMechanism = PresentationMechanismEnum.DCQL,
                        ),
                    )

                    holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                        .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                        .error.shouldNotBeNull()
                }

                "if available despite others with correct format or correct attribute, but not both" {
                    holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeSdJwtCredential(holderKeyMaterial, MobileDrivingLicenceScheme)
                    holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

                    val authnRequest = verifierOid4vp.createAuthnRequest(
                        requestOptions = RequestOptions(
                            credentials = setOf(
                                RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, SD_JWT)
                            ),
                            presentationMechanism = PresentationMechanismEnum.DCQL
                        ),
                    )

                    val authnResponse =
                        holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

                    verifierOid4vp.validateAuthnResponse(authnResponse.url)
                        .shouldBeInstanceOf<AuthnResponseResult.VerifiableDCQLPresentationValidationResults>()
                        .validationResults.values.first()
                        .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
                        .verifiableCredentialSdJwt.verifiableCredentialType shouldBe ConstantIndex.AtomicAttribute2023.sdJwtType
                }
            }
        }

        "support for mso credential request" - {
            "when using presentation exchange" - {
                "if not available despite others with correct format or correct attribute, but not both" {
                    holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeIsoCredential(holderKeyMaterial, MobileDrivingLicenceScheme)

                    val authnRequest = verifierOid4vp.createAuthnRequest(
                        requestOptions = RequestOptions(
                            credentials = setOf(
                                RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, ISO_MDOC)
                            )
                        ),
                    )
                    holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                        .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                        .error.shouldNotBeNull()
                }

                "if available despite others with correct format or correct attribute, but not both" {
                    holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeIsoCredential(holderKeyMaterial, MobileDrivingLicenceScheme)

                    val authnRequest = verifierOid4vp.createAuthnRequest(
                        requestOptions = RequestOptions(
                            credentials = setOf(
                                RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, ISO_MDOC)
                            )
                        ),
                    )
                    val authnResponse = holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                        .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

                    verifierOid4vp.validateAuthnResponse(authnResponse.url)
                        .shouldBeInstanceOf<AuthnResponseResult.SuccessIso>()
                }
            }
            "when using dcql" - {
                "if not available despite others with correct format or correct attribute, but not both" {
                    holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeIsoCredential(holderKeyMaterial, MobileDrivingLicenceScheme)

                    val authnRequest = verifierOid4vp.createAuthnRequest(
                        requestOptions = RequestOptions(
                            credentials = setOf(
                                RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, ISO_MDOC)
                            ),
                            presentationMechanism = PresentationMechanismEnum.DCQL,
                        ),
                    )

                    holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                        .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                        .error.shouldNotBeNull()
                }

                "if available despite others with correct format or correct attribute, but not both" {
                    holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeIsoCredential(holderKeyMaterial, MobileDrivingLicenceScheme)

                    val authnRequest = verifierOid4vp.createAuthnRequest(
                        requestOptions = RequestOptions(
                            credentials = setOf(
                                RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, ISO_MDOC)
                            ),
                            presentationMechanism = PresentationMechanismEnum.DCQL
                        ),
                    )

                    val authnResponse =
                        holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

                    verifierOid4vp.validateAuthnResponse(authnResponse.url)
                        .shouldBeInstanceOf<AuthnResponseResult.VerifiableDCQLPresentationValidationResults>()
                }
            }
        }
    }


    "presentation of multiple credentials with different formats in one request/response" {
        holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
        holderAgent.storeIsoCredential(holderKeyMaterial, MobileDrivingLicenceScheme)

        val authnRequest = verifierOid4vp.createAuthnRequest(
            requestOptions = RequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, PLAIN_JWT),
                    RequestOptionsCredential(MobileDrivingLicenceScheme, ISO_MDOC)
                )
            ),
        )
        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val validationResults = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.VerifiablePresentationValidationResults>()
        validationResults.validationResults.size shouldBe 2
    }

    "presentation of multiple SD-JWT credentials in one request/response" {
        holderAgent.storeSdJwtCredential(holderKeyMaterial, EuPidScheme)
        holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

        val requestOptions = RequestOptions(
            credentials = setOf(
                RequestOptionsCredential(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = SD_JWT,
                    requestedAttributes = setOf(ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH),
                ),
                RequestOptionsCredential(
                    credentialScheme = EuPidScheme,
                    representation = SD_JWT,
                    requestedAttributes = setOf(
                        EuPidScheme.Attributes.FAMILY_NAME,
                        EuPidScheme.Attributes.GIVEN_NAME
                    ),
                )
            )
        )
        val authnRequest = verifierOid4vp.createAuthnRequest(requestOptions)

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val groupedResult = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.VerifiablePresentationValidationResults>()
        groupedResult.validationResults.size shouldBe 2
        groupedResult.validationResults.forEach { result ->
            result.shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
            result.reconstructed.entries.shouldNotBeEmpty()
            when (result.verifiableCredentialSdJwt.verifiableCredentialType) {
                EuPidScheme.sdJwtType -> {
                    result.reconstructed[EuPidScheme.Attributes.FAMILY_NAME].shouldNotBeNull()
                    result.reconstructed[EuPidScheme.Attributes.GIVEN_NAME].shouldNotBeNull()
                }

                ConstantIndex.AtomicAttribute2023.sdJwtType -> {
                    result.reconstructed[ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH].shouldNotBeNull()
                }

                else -> {
                    fail("Unexpected SD-JWT type: ${result.verifiableCredentialSdJwt.verifiableCredentialType}")
                }
            }
        }
    }
})

private fun AuthenticationRequestParameters.serialize(): String = vckJsonSerializer.encodeToString(this)

private suspend fun Holder.storeJwtCredential(
    holderKeyMaterial: KeyMaterial,
    credentialScheme: ConstantIndex.CredentialScheme,
) {
    storeCredential(
        IssuerAgent(
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        ).issueCredential(
            DummyCredentialDataProvider.getCredential(
                holderKeyMaterial.publicKey,
                credentialScheme,
                PLAIN_JWT,
            ).getOrThrow()
        ).getOrThrow().toStoreCredentialInput()
    )
}

private suspend fun Holder.storeSdJwtCredential(
    holderKeyMaterial: KeyMaterial,
    credentialScheme: ConstantIndex.CredentialScheme,
) {
    storeCredential(
        IssuerAgent(
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        ).issueCredential(
            DummyCredentialDataProvider.getCredential(
                holderKeyMaterial.publicKey,
                credentialScheme,
                SD_JWT,
            ).getOrThrow()
        ).getOrThrow().toStoreCredentialInput()
    )
}

private suspend fun Holder.storeIsoCredential(
    holderKeyMaterial: KeyMaterial,
    credentialScheme: ConstantIndex.CredentialScheme,
) = storeCredential(
    IssuerAgent(
        keyMaterial = EphemeralKeyWithSelfSignedCert(),
        identifier = "https://issuer.example.com/".toUri(),
        randomSource = RandomSource.Default
    ).issueCredential(
        DummyCredentialDataProvider.getCredential(
            holderKeyMaterial.publicKey,
            credentialScheme,
            ISO_MDOC,
        ).getOrThrow()
    ).getOrThrow().toStoreCredentialInput()
)
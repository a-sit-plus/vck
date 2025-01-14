package at.asitplus.wallet.lib.openid

import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import io.kotest.assertions.fail
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

class OpenId4VpCombinedProtocolTest : FreeSpec({

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
                            RequestOptionsCredential(
                                ConstantIndex.AtomicAttribute2023, ConstantIndex.CredentialRepresentation.PLAIN_JWT
                            )
                        )
                    )
                )
                shouldThrow<OAuth2Exception> {
                    holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                }
            }

            "if available despite others" {
                holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeJwtCredential(holderKeyMaterial, MobileDrivingLicenceScheme)
                holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

                val authnRequest = verifierOid4vp.createAuthnRequest(
                    requestOptions = RequestOptions(
                        credentials = setOf(
                            RequestOptionsCredential(
                                ConstantIndex.AtomicAttribute2023,
                                ConstantIndex.CredentialRepresentation.PLAIN_JWT
                            )
                        )
                    )
                )

                val authnResponse = holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

                val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
                    .shouldBeInstanceOf<AuthnResponseResult.Success>()
                result.vp.verifiableCredentials.shouldNotBeEmpty()
                result.vp.verifiableCredentials.forEach {
                    it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
                }
            }
        }

        "support for sd jwt credential request" - {
            "if not available despite others with correct format or correct attribute, but not both" {
                holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeSdJwtCredential(holderKeyMaterial, MobileDrivingLicenceScheme)
                holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

                val authnRequest = verifierOid4vp.createAuthnRequest(
                    requestOptions = RequestOptions(
                        credentials = setOf(
                            RequestOptionsCredential(
                                ConstantIndex.AtomicAttribute2023, ConstantIndex.CredentialRepresentation.SD_JWT
                            )
                        )
                    )
                )
                shouldThrow<OAuth2Exception> {
                    holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                }
            }

            "if available despite others with correct format or correct attribute, but not both" {
                holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeSdJwtCredential(holderKeyMaterial, MobileDrivingLicenceScheme)
                holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

                val authnRequest = verifierOid4vp.createAuthnRequest(
                    requestOptions = RequestOptions(
                        credentials = setOf(
                            RequestOptionsCredential(
                                ConstantIndex.AtomicAttribute2023, ConstantIndex.CredentialRepresentation.SD_JWT
                            )
                        )
                    )
                )
                val authnResponse = holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

                val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
                    .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
                result.verifiableCredentialSdJwt.verifiableCredentialType shouldBe ConstantIndex.AtomicAttribute2023.sdJwtType
            }
        }

        "support for mso credential request" - {
            "if not available despite others with correct format or correct attribute, but not both" {
                holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeIsoCredential(holderKeyMaterial, MobileDrivingLicenceScheme)

                val authnRequest = verifierOid4vp.createAuthnRequest(
                    requestOptions = RequestOptions(
                        credentials = setOf(
                            RequestOptionsCredential(
                                ConstantIndex.AtomicAttribute2023, ConstantIndex.CredentialRepresentation.ISO_MDOC
                            )
                        )
                    ),
                )
                shouldThrow<OAuth2Exception> {
                    holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                }
            }

            "if available despite others with correct format or correct attribute, but not both" {
                holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeIsoCredential(holderKeyMaterial, MobileDrivingLicenceScheme)

                val authnRequest = verifierOid4vp.createAuthnRequest(
                    requestOptions = RequestOptions(
                        credentials = setOf(
                            RequestOptionsCredential(
                                ConstantIndex.AtomicAttribute2023,
                                ConstantIndex.CredentialRepresentation.ISO_MDOC
                            )
                        )
                    ),
                )
                val authnResponse = holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

                verifierOid4vp.validateAuthnResponse(authnResponse.url)
                    .shouldBeInstanceOf<AuthnResponseResult.SuccessIso>()
            }
        }
    }


    "presentation of multiple credentials with different formats in one request/response" {
        holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
        holderAgent.storeIsoCredential(holderKeyMaterial, MobileDrivingLicenceScheme)

        val authnRequest = verifierOid4vp.createAuthnRequest(
            requestOptions = RequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(
                        ConstantIndex.AtomicAttribute2023, ConstantIndex.CredentialRepresentation.PLAIN_JWT
                    ),
                    RequestOptionsCredential(
                        MobileDrivingLicenceScheme, ConstantIndex.CredentialRepresentation.ISO_MDOC
                    )
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
                    representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                    requestedAttributes = listOf(ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH),
                ),
                RequestOptionsCredential(
                    credentialScheme = EuPidScheme,
                    representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                    requestedAttributes = listOf(
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

private suspend fun Holder.storeJwtCredential(
    holderKeyMaterial: KeyMaterial,
    credentialScheme: ConstantIndex.CredentialScheme,
) {
    storeCredential(
        IssuerAgent().issueCredential(
            DummyCredentialDataProvider.getCredential(
                holderKeyMaterial.publicKey,
                credentialScheme,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT,
            ).getOrThrow()
        ).getOrThrow().toStoreCredentialInput()
    )
}

private suspend fun Holder.storeSdJwtCredential(
    holderKeyMaterial: KeyMaterial,
    credentialScheme: ConstantIndex.CredentialScheme,
) {
    storeCredential(
        IssuerAgent().issueCredential(
            DummyCredentialDataProvider.getCredential(
                holderKeyMaterial.publicKey,
                credentialScheme,
                ConstantIndex.CredentialRepresentation.SD_JWT,
            ).getOrThrow()
        ).getOrThrow().toStoreCredentialInput()
    )
}

private suspend fun Holder.storeIsoCredential(
    holderKeyMaterial: KeyMaterial,
    credentialScheme: ConstantIndex.CredentialScheme,
) = storeCredential(
    IssuerAgent(EphemeralKeyWithSelfSignedCert()).issueCredential(
        DummyCredentialDataProvider.getCredential(
            holderKeyMaterial.publicKey,
            credentialScheme,
            ConstantIndex.CredentialRepresentation.ISO_MDOC,
        ).getOrThrow()
    ).getOrThrow().toStoreCredentialInput()
)
package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import io.kotest.assertions.fail
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

class OidcSiopCombinedProtocolTest : FreeSpec({

    lateinit var relyingPartyUrl: String

    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial

    lateinit var holderAgent: Holder

    lateinit var holderSiop: OidcSiopWallet
    lateinit var verifierSiop: OidcSiopVerifier

    beforeEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithoutCert()
        relyingPartyUrl = "https://example.com/rp/${uuid4()}"
        holderAgent = HolderAgent(holderKeyMaterial)

        holderSiop = OidcSiopWallet(
            keyMaterial = holderKeyMaterial,
            holder = holderAgent,
        )
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyMaterial,
            relyingPartyUrl = relyingPartyUrl,
        )
    }

    "support for format holder specification" - {

        "support for plain jwt credential request" - {
            "if not available despite others with correct format or correct attribute, but not both" {
                holderAgent.storeJwtCredential(holderKeyMaterial, MobileDrivingLicenceScheme)
                holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = OidcSiopVerifier.RequestOptions(
                        credentials = setOf(
                            OidcSiopVerifier.RequestOptionsCredential(
                                ConstantIndex.AtomicAttribute2023, CredentialRepresentation.PLAIN_JWT
                            )
                        )
                    )
                )
                shouldThrow<OAuth2Exception> {
                    holderSiop.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                }
            }

            "if available despite others" {
                holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeJwtCredential(holderKeyMaterial, MobileDrivingLicenceScheme)
                holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = OidcSiopVerifier.RequestOptions(
                        credentials = setOf(
                            OidcSiopVerifier.RequestOptionsCredential(
                                ConstantIndex.AtomicAttribute2023,
                                CredentialRepresentation.PLAIN_JWT
                            )
                        )
                    )
                )

                val authnResponse = holderSiop.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

                val result = verifierSiop.validateAuthnResponse(authnResponse.url)
                    .shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
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

                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = OidcSiopVerifier.RequestOptions(
                        credentials = setOf(
                            OidcSiopVerifier.RequestOptionsCredential(
                                ConstantIndex.AtomicAttribute2023, CredentialRepresentation.SD_JWT
                            )
                        )
                    )
                )
                shouldThrow<OAuth2Exception> {
                    holderSiop.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                }
            }

            "if available despite others with correct format or correct attribute, but not both" {
                holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeSdJwtCredential(holderKeyMaterial, MobileDrivingLicenceScheme)
                holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = OidcSiopVerifier.RequestOptions(
                        credentials = setOf(
                            OidcSiopVerifier.RequestOptionsCredential(
                                ConstantIndex.AtomicAttribute2023, CredentialRepresentation.SD_JWT
                            )
                        )
                    )
                )
                val authnResponse = holderSiop.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

                val result = verifierSiop.validateAuthnResponse(authnResponse.url)
                    .shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessSdJwt>()
                result.sdJwt.type?.shouldContain(ConstantIndex.AtomicAttribute2023.vcType)
            }
        }

        "support for mso credential request" - {
            "if not available despite others with correct format or correct attribute, but not both" {
                holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeIsoCredential(holderKeyMaterial, MobileDrivingLicenceScheme)

                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = OidcSiopVerifier.RequestOptions(
                        credentials = setOf(
                            OidcSiopVerifier.RequestOptionsCredential(
                                ConstantIndex.AtomicAttribute2023, CredentialRepresentation.ISO_MDOC
                            )
                        )
                    ),
                )
                shouldThrow<OAuth2Exception> {
                    holderSiop.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                }
            }

            "if available despite others with correct format or correct attribute, but not both" {
                holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeIsoCredential(holderKeyMaterial, MobileDrivingLicenceScheme)

                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = OidcSiopVerifier.RequestOptions(
                        credentials = setOf(
                            OidcSiopVerifier.RequestOptionsCredential(
                                ConstantIndex.AtomicAttribute2023,
                                CredentialRepresentation.ISO_MDOC
                            )
                        )
                    ),
                )
                val authnResponse = holderSiop.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

                verifierSiop.validateAuthnResponse(authnResponse.url)
                    .shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessIso>()
            }
        }
    }


    "presentation of multiple credentials with different formats in one request/response" {
        holderAgent.storeJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
        holderAgent.storeIsoCredential(holderKeyMaterial, MobileDrivingLicenceScheme)

        val authnRequest = verifierSiop.createAuthnRequest(
            requestOptions = OidcSiopVerifier.RequestOptions(
                credentials = setOf(
                    OidcSiopVerifier.RequestOptionsCredential(
                        ConstantIndex.AtomicAttribute2023, CredentialRepresentation.PLAIN_JWT
                    ),
                    OidcSiopVerifier.RequestOptionsCredential(
                        MobileDrivingLicenceScheme, CredentialRepresentation.ISO_MDOC
                    )
                )
            ),
        )
        val authnResponse = holderSiop.createAuthnResponse(authnRequest.serialize()).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val validationResults = verifierSiop.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.VerifiablePresentationValidationResults>()
        validationResults.validationResults.size shouldBe 2
    }

    "presentation of multiple SD-JWT credentials in one request/response" {
        holderAgent.storeSdJwtCredential(holderKeyMaterial, EuPidScheme)
        holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

        val requestOptions = OidcSiopVerifier.RequestOptions(
            credentials = setOf(
                OidcSiopVerifier.RequestOptionsCredential(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = CredentialRepresentation.SD_JWT,
                    requestedAttributes = listOf(CLAIM_DATE_OF_BIRTH),
                ),
                OidcSiopVerifier.RequestOptionsCredential(
                    credentialScheme = EuPidScheme,
                    representation = CredentialRepresentation.SD_JWT,
                    requestedAttributes = listOf(
                        EuPidScheme.Attributes.FAMILY_NAME,
                        EuPidScheme.Attributes.GIVEN_NAME
                    ),
                )
            )
        )
        val authnRequest = verifierSiop.createAuthnRequest(requestOptions)

        val authnResponse = holderSiop.createAuthnResponse(authnRequest.serialize()).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val groupedResult = verifierSiop.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.VerifiablePresentationValidationResults>()
        groupedResult.validationResults.size shouldBe 2
        groupedResult.validationResults.forEach { result ->
            result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessSdJwt>()
            result.disclosures.shouldNotBeEmpty()
            when (result.sdJwt.verifiableCredentialType) {
                EuPidScheme.sdJwtType -> {
                    result.disclosures.firstOrNull { it.claimName == EuPidScheme.Attributes.FAMILY_NAME }
                        .shouldNotBeNull()
                    result.disclosures.firstOrNull { it.claimName == EuPidScheme.Attributes.GIVEN_NAME }
                        .shouldNotBeNull()
                }

                ConstantIndex.AtomicAttribute2023.sdJwtType -> {
                    result.disclosures.firstOrNull() { it.claimName == CLAIM_DATE_OF_BIRTH }.shouldNotBeNull()
                }

                else -> {
                    fail("Unexpected SD-JWT type: ${result.sdJwt.verifiableCredentialType}")
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
        IssuerAgent(
            EphemeralKeyWithoutCert(),
            DummyCredentialDataProvider(),
        ).issueCredential(
            DummyCredentialDataProvider().getCredential(
                holderKeyMaterial.publicKey,
                credentialScheme,
                CredentialRepresentation.PLAIN_JWT,
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
            EphemeralKeyWithoutCert(),
            DummyCredentialDataProvider(),
        ).issueCredential(
            DummyCredentialDataProvider().getCredential(
                holderKeyMaterial.publicKey,
                credentialScheme,
                CredentialRepresentation.SD_JWT,
            ).getOrThrow()
        ).getOrThrow().toStoreCredentialInput()
    )
}

private suspend fun Holder.storeIsoCredential(
    holderKeyMaterial: KeyMaterial,
    credentialScheme: ConstantIndex.CredentialScheme,
) = storeCredential(
    IssuerAgent(
        EphemeralKeyWithSelfSignedCert(),
        DummyCredentialDataProvider(),
    ).issueCredential(
        DummyCredentialDataProvider().getCredential(
            holderKeyMaterial.publicKey,
            credentialScheme,
            CredentialRepresentation.ISO_MDOC,
        ).getOrThrow()
    ).getOrThrow().toStoreCredentialInput()
)

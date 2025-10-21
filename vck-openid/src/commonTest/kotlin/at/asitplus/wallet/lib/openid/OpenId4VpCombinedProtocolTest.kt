package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.RequestOptionsCredential
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
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.AssertionErrorBuilder.Companion.fail
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

private fun AuthenticationRequestParameters.serialize(): String = vckJsonSerializer.encodeToString(this)

val OpenId4VpCombinedProtocolTest by testSuite {

    withFixtureGenerator {
        object {
            val holderKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
            val verifierKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
            val clientId: String = "https://example.com/rp/${uuid4()}"
            val holderAgent: Holder = HolderAgent(holderKeyMaterial)
            val holderOid4vp: OpenId4VpHolder = OpenId4VpHolder(
                keyMaterial = holderKeyMaterial,
                holder = holderAgent,
                randomSource = RandomSource.Default,
            )
            val verifierOid4vp: OpenId4VpVerifier = OpenId4VpVerifier(
                keyMaterial = verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.RedirectUri(clientId),
            )
        }
    } - {

        test("plain jwt: if not available despite others with correct format or correct attribute, but not both") {
            it.holderAgent.storeJwtCredential(it.holderKeyMaterial, MobileDrivingLicenceScheme)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
                    )
                )
            )
            it.holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .error.shouldNotBeNull()
        }

        test("plain jwt: if available despite others") {
            it.holderAgent.storeJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeJwtCredential(it.holderKeyMaterial, MobileDrivingLicenceScheme)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
                    )
                )
            )

            val authnResponse =
                it.holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
                .map { it.vcJws }.forEach {
                    it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
                }
        }

        test("sd-jwt presex: if not available despite others with correct format or correct attribute, but not both") {
            it.holderAgent.storeJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, MobileDrivingLicenceScheme)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, SD_JWT)
                    )
                )
            )
            it.holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .error.shouldNotBeNull()
        }

        test("sd-jwt presex: if available despite others with correct format or correct attribute, but not both") {
            it.holderAgent.storeJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, MobileDrivingLicenceScheme)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, SD_JWT)
                    )
                ),
            )
            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
                .verifiableCredentialSdJwt.verifiableCredentialType shouldBe ConstantIndex.AtomicAttribute2023.sdJwtType
        }

        test("sd-jwt dcql: if not available despite others with correct format or correct attribute, but not both") {
            it.holderAgent.storeJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, MobileDrivingLicenceScheme)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

            val authnRequest = it.verifierOid4vp.prepareAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, SD_JWT)
                    ),
                    presentationMechanism = PresentationMechanismEnum.DCQL,
                ),
            )

            it.holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .error.shouldNotBeNull()
        }

        test("sd-jwt dcql: if available despite others with correct format or correct attribute, but not both") {
            it.holderAgent.storeJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, MobileDrivingLicenceScheme)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, SD_JWT)
                    ),
                    presentationMechanism = PresentationMechanismEnum.DCQL
                ),
            )

            val authnResponse =
                it.holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.VerifiableDCQLPresentationValidationResults>()
                .validationResults.values.first().first()
                .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
                .verifiableCredentialSdJwt.verifiableCredentialType shouldBe ConstantIndex.AtomicAttribute2023.sdJwtType
        }

        "mdoc presex: if not available despite others with correct format or correct attribute, but not both" { it ->
            it.holderAgent.storeJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, MobileDrivingLicenceScheme)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, ISO_MDOC)
                    )
                ),
            )
            it.holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .error.shouldNotBeNull()
        }

        "mdoc presex: if available despite others with correct format or correct attribute, but not both" { it ->
            it.holderAgent.storeJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, MobileDrivingLicenceScheme)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, ISO_MDOC)
                    )
                ),
            )
            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.SuccessIso>()
        }

        "mdoc dcql: if not available despite others with correct format or correct attribute, but not both" { it ->
            it.holderAgent.storeJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, MobileDrivingLicenceScheme)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, ISO_MDOC)
                    ),
                    presentationMechanism = PresentationMechanismEnum.DCQL,
                ),
            )

            it.holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .error.shouldNotBeNull()
        }

        "mdoc dcql: if available despite others with correct format or correct attribute, but not both" { it ->
            it.holderAgent.storeJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, MobileDrivingLicenceScheme)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, ISO_MDOC)
                    ),
                    presentationMechanism = PresentationMechanismEnum.DCQL
                ),
            )

            val authnResponse =
                it.holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.VerifiableDCQLPresentationValidationResults>()
        }

        "presentation of multiple credentials with different formats in one request/response" { it ->
            it.holderAgent.storeJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, MobileDrivingLicenceScheme)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, PLAIN_JWT),
                        RequestOptionsCredential(MobileDrivingLicenceScheme, ISO_MDOC)
                    )
                ),
            )
            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            val validationResults = it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.VerifiablePresentationValidationResults>()
            validationResults.validationResults.size shouldBe 2
        }

        "presentation of multiple SD-JWT credentials in one request/response" { it ->
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, EuPidScheme)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

            val requestOptions = OpenId4VpRequestOptions(
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
            val authnRequest = it.verifierOid4vp.createAuthnRequest(requestOptions)

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            val groupedResult = it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
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
    }
}

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

package at.asitplus.wallet.lib.openid

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications: Credential subject is now a JsonElement
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLJwtVcCredentialQuery
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
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.AssertionErrorBuilder.Companion.fail
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

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
                    presentationRequest = CredentialPresentationRequestBuilder(
                        credentials = setOf(
                            RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
                        ),
                    ).toDCQLRequest()
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
                    presentationRequest = CredentialPresentationRequestBuilder(
                        credentials = setOf(
                            RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
                        )
                    ).toDCQLRequest(),
                )
            )

            val authnResponse =
                it.holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .allValidationResults.values
                .shouldBeSingleton().first().shouldBeSingleton().first().getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
                .map { it.vcJws }.forEach {
                    it.vc.credentialSubject.shouldBeInstanceOf<JsonElement>().also { credentialSubject ->
                        shouldNotThrowAny {
                            Json.decodeFromJsonElement(AtomicAttribute2023.serializer(), credentialSubject)
                        }
                    }
                }
        }

        test("plain jwt: send plain if no cryptographic holder binding") {
            it.holderAgent.storeJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeJwtCredential(it.holderKeyMaterial, MobileDrivingLicenceScheme)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        credentials = setOf(
                            RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
                        )
                    ).toDCQLRequest()?.let {
                        CredentialPresentationRequest.DCQLRequest(
                            it.dcqlQuery.copy(
                                credentials = DCQLCredentialQueryList(
                                    it.dcqlQuery.credentials.map {
                                        it as DCQLJwtVcCredentialQuery
                                    }.map {
                                        it.copy(
                                            requireCryptographicHolderBinding = false
                                        )
                                    }.toNonEmptyList()
                                )
                            )
                        )
                    },
                )
            )

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            val vcFreshnessSummary = it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .allValidationResults.values.shouldBeSingleton().first().shouldBeSingleton().first().getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessUnsignedVcJws>()
                .vc
            vcFreshnessSummary.vcJws.vc.credentialSubject.shouldBeInstanceOf<JsonObject>()
            vcFreshnessSummary.freshnessSummary.isFresh.shouldBeTrue()
        }

        test("sd-jwt presex: if not available despite others with correct format or correct attribute, but not both") {
            it.holderAgent.storeJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, MobileDrivingLicenceScheme)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        credentials = setOf(
                            RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, SD_JWT)
                        )
                    ).toPresentationExchangeRequest()
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
                    presentationRequest = CredentialPresentationRequestBuilder(
                        credentials = setOf(
                            RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, SD_JWT)
                        )
                    ).toPresentationExchangeRequest(),
                ),
            )
            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultPresentationExchange>()
                .inputDescriptorResponseValidations.values.shouldBeSingleton().first().getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
                .verifiableCredentialSdJwt.verifiableCredentialType shouldBe ConstantIndex.AtomicAttribute2023.sdJwtType
        }

        test("sd-jwt dcql: if not available despite others with correct format or correct attribute, but not both") {
            it.holderAgent.storeJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, MobileDrivingLicenceScheme)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

            val authnRequest = it.verifierOid4vp.prepareAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        credentials = setOf(
                            RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, SD_JWT)
                        ),
                    ).toDCQLRequest(),
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
                    presentationRequest = CredentialPresentationRequestBuilder(
                        credentials = setOf(
                            RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, SD_JWT)
                        ),
                    ).toDCQLRequest(),
                ),
            )

            val authnResponse =
                it.holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .allValidationResults.values.shouldBeSingleton().first().shouldBeSingleton().first().getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
                .verifiableCredentialSdJwt.verifiableCredentialType shouldBe ConstantIndex.AtomicAttribute2023.sdJwtType
        }

        "mdoc presex: if not available despite others with correct format or correct attribute, but not both" { it ->
            it.holderAgent.storeJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, MobileDrivingLicenceScheme)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        credentials = setOf(
                            RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, ISO_MDOC)
                        )
                    ).toPresentationExchangeRequest(),
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
                    presentationRequest = CredentialPresentationRequestBuilder(
                        credentials = setOf(
                            RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, ISO_MDOC)
                        )
                    ).toPresentationExchangeRequest(),
                ),
            )
            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultPresentationExchange>()
                .inputDescriptorResponseValidations.values.shouldBeSingleton().first().getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessIso>()
        }

        "mdoc dcql: if not available despite others with correct format or correct attribute, but not both" { it ->
            it.holderAgent.storeJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, MobileDrivingLicenceScheme)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        credentials = setOf(
                            RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, ISO_MDOC)
                        ),
                    ).toDCQLRequest(),
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
                    presentationRequest = CredentialPresentationRequestBuilder(
                        credentials = setOf(
                            RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, ISO_MDOC)
                        ),
                    ).toDCQLRequest(),
                ),
            )

            val authnResponse =
                it.holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
        }

        "presentation of multiple credentials with different formats in one request/response" { it ->
            it.holderAgent.storeJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, MobileDrivingLicenceScheme)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        credentials = setOf(
                            RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, PLAIN_JWT),
                            RequestOptionsCredential(MobileDrivingLicenceScheme, ISO_MDOC)
                        )
                    ).toPresentationExchangeRequest(),
                ),
            )
            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultPresentationExchange>()
                .inputDescriptorResponseValidations.values.shouldHaveSize(2)
        }

        "presentation of multiple SD-JWT credentials in one request/response" { it ->
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, EuPidScheme)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

            val requestOptions = OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
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
                ).toPresentationExchangeRequest(),
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(requestOptions)

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            val groupedResult = it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultPresentationExchange>()
                .inputDescriptorResponseValidations.values.map {
                    it.getOrThrow()
                }
            groupedResult.size shouldBe 2
            groupedResult.forEach { result ->
                result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
                result.reconstructedJsonObject.entries.shouldNotBeEmpty()
                when (result.verifiableCredentialSdJwt.verifiableCredentialType) {
                    EuPidScheme.sdJwtType -> {
                        result.reconstructedJsonObject[EuPidScheme.Attributes.FAMILY_NAME].shouldNotBeNull()
                        result.reconstructedJsonObject[EuPidScheme.Attributes.GIVEN_NAME].shouldNotBeNull()
                    }

                    ConstantIndex.AtomicAttribute2023.sdJwtType -> {
                        result.reconstructedJsonObject[ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH].shouldNotBeNull()
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

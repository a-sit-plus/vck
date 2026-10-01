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
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialQuery
import at.asitplus.openid.dcql.DCQLIsoMdocZkCredentialQuery
import at.asitplus.openid.dcql.DCQLJwtVcCredentialQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.eupidsdjwt.EU_PID_SD_JWT_VCT
import at.asitplus.wallet.eupidsdjwt.EuPidSdJwtDataElements
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.DCQLMatchingResult
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreIsoMdoc
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStorePlainJwt
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreSdJwt
import at.asitplus.wallet.mdl.MDL_DOCTYPE
import com.benasher44.uuid.uuid4
import io.kotest.assertions.AssertionErrorBuilder.Companion.fail
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

val OpenId4VpCombinedProtocolTest by matrixSuite {

    fixture {
        runBlocking {
            val mdlScheme = AttributeIndex.resolveIdentifier(MDL_DOCTYPE, ISO_MDOC)
            val euPidSdJwtScheme = AttributeIndex.resolveIdentifier(EU_PID_SD_JWT_VCT, SD_JWT)
            val euPidScheme = AttributeIndex.resolveIdentifier("EuPid2023", PLAIN_JWT)
            object {
                val mdlScheme = mdlScheme
                val euPidSdJwtScheme = euPidSdJwtScheme
                val euPidScheme = euPidScheme
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
        }
    } - {
        test("plain jwt: if not available despite others with correct format or correct attribute, but not both") {
            issueAndStorePlainJwt(it.holderAgent, it.holderKeyMaterial, it.euPidScheme)
            issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
                    ).toDCQLRequest()
                ),
                creationOptions = CreationOptions.Query("https://example.com")
            ).getOrThrow().url
            it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .error.shouldNotBeNull()
        }

        test("plain jwt: if available despite others") {
            issueAndStorePlainJwt(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStorePlainJwt(it.holderAgent, it.holderKeyMaterial, it.euPidScheme)
            issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)


            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
                    ).toDCQLRequest()
                ),
                creationOptions = CreationOptions.Query("https://example.com")
            ).getOrThrow().url

            val authnResponse =
                it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values
                .shouldBeSingleton().first().shouldBeSingleton().first().getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
                .map { it.vcJws }.forEach {
                    it.vc.credentialSubject.shouldBeInstanceOf<JsonElement>().also { credentialSubject ->
                        shouldNotThrowAny {
                            AtomicAttribute2023.fromJsonElement(credentialSubject)
                        }
                    }
                }
        }

        test("plain jwt: send plain if no cryptographic holder binding") {
            issueAndStorePlainJwt(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStorePlainJwt(it.holderAgent, it.holderKeyMaterial, it.mdlScheme)
            issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

            val requestOptions = OpenId4VpRequestOptions(
                CredentialPresentationRequestBuilder(
                    RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
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

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = requestOptions,
                creationOptions = CreationOptions.Query("https://example.com")
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            val vcFreshnessSummary = it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.shouldBeSingleton().first().shouldBeSingleton()
                .first()
                .getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessUnsigned>()
                .vc
            vcFreshnessSummary.vcJws.vc.credentialSubject.shouldBeInstanceOf<JsonObject>()
            vcFreshnessSummary.freshnessSummary.isFresh.shouldBeTrue()
        }

        test("sd-jwt dcql: if not available despite others with correct format or correct attribute, but not both") {
            issueAndStorePlainJwt(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial, it.euPidSdJwtScheme)
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, SD_JWT)
                    ).toDCQLRequest()
                ),
                creationOptions = CreationOptions.Query("https://example.com")
            ).getOrThrow().url

            it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .error.shouldNotBeNull()
        }

        test("sd-jwt dcql: if available despite others with correct format or correct attribute, but not both") {
            issueAndStorePlainJwt(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial, it.euPidSdJwtScheme)
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, SD_JWT)
                    ).toDCQLRequest()
                ),
                creationOptions = CreationOptions.Query("https://example.com")
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.shouldBeSingleton().first().shouldBeSingleton()
                .first()
                .getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
                .verifiableCredentialSdJwt.verifiableCredentialType shouldBe ConstantIndex.AtomicAttribute2023.sdJwtType
        }

        "mdoc dcql: if not available despite others with correct format or correct attribute, but not both" {
            issueAndStorePlainJwt(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, it.mdlScheme)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, ISO_MDOC)
                    ).toDCQLRequest()
                ),
                creationOptions = CreationOptions.Query("https://example.com")
            ).getOrThrow().url

            it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .error.shouldNotBeNull()
        }

        "mdoc dcql: if available despite others with correct format or correct attribute, but not both" {
            issueAndStorePlainJwt(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, it.mdlScheme)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, ISO_MDOC)
                    ).toDCQLRequest()
                ),
                creationOptions = CreationOptions.Query("https://example.com")
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .submissionRequirementsValidationResult.isSuccess.shouldBeTrue()
        }

        "mdoc dcql: presenting for incorrect query identifiers is invalid" {
            issueAndStorePlainJwt(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, it.mdlScheme)

            val dcqlRequest = CredentialPresentationRequestBuilder(
                RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, ISO_MDOC)
            ).toDCQLRequest().shouldNotBeNull()

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(dcqlRequest),
                creationOptions = CreationOptions.Query("https://example.com")
            ).getOrThrow().url

            val preparationState =
                it.holderOid4vp.startAuthorizationResponsePreparation(authnRequest).getOrThrow()

            val matchesWithBadQueryIdentifiers = it.holderAgent
                .matchPresentationRequestAgainstCredentialStore(dcqlRequest).getOrThrow()
                .shouldBeInstanceOf<DCQLMatchingResult<SubjectCredentialStore.StoreEntry>>()
                .matchingResult.credentialQueryMatches.mapKeys {
                    DCQLCredentialQueryIdentifier(it.key.string + "1")
                }

            val authnResponse = it.holderOid4vp.finalizeAuthorizationResponse(
                preparationState = preparationState,
                credentialPresentation = CredentialPresentation.DCQLPresentation(
                    presentationRequest = dcqlRequest,
                    credentialQuerySubmissions = matchesWithBadQueryIdentifiers
                ),
            ).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            // creation should fail because submission requirements are not satisfied
            authnResponse.error.shouldNotBeNull()
        }

        "mdoc dcql: presenting incorrect credentials yields invalid submission validation result" {
            issueAndStorePlainJwt(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, it.mdlScheme)

            val dcqlRequest = CredentialPresentationRequestBuilder(
                RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, ISO_MDOC)
            ).toDCQLRequest().shouldNotBeNull()

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(dcqlRequest),
                creationOptions = CreationOptions.Query("https://example.com")
            ).getOrThrow().url

            val preparationState =
                it.holderOid4vp.startAuthorizationResponsePreparation(authnRequest).getOrThrow()

            val otherDcqlQuery = CredentialPresentationRequestBuilder(
                RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, SD_JWT)
            ).toDCQLRequest().shouldNotBeNull().dcqlQuery

            val otherQueryWithOriginalIds = CredentialPresentationRequest.DCQLRequest(
                dcqlRequest.dcqlQuery.copy(
                    credentials = DCQLCredentialQueryList(
                        dcqlRequest.dcqlQuery.credentials.zip(otherDcqlQuery.credentials) { good, bad ->
                            when (bad) {
                                is DCQLIsoMdocCredentialQuery -> bad.copy(id = good.id)
                                is DCQLIsoMdocZkCredentialQuery -> bad.copy(id = good.id)
                                is DCQLJwtVcCredentialQuery -> bad.copy(id = good.id)
                                is DCQLSdJwtCredentialQuery -> bad.copy(id = good.id)
                            }
                        }.toNonEmptyList()
                    )
                )
            )

            val badMatches = it.holderAgent
                .matchPresentationRequestAgainstCredentialStore(otherQueryWithOriginalIds).getOrThrow()
                .shouldBeInstanceOf<DCQLMatchingResult<SubjectCredentialStore.StoreEntry>>()
                .matchingResult.credentialQueryMatches

            badMatches.values.flatten().forEach {
                it.credential.shouldBeInstanceOf<SubjectCredentialStore.StoreEntry.SdJwt>()
            }

            val authnResponse = it.holderOid4vp.finalizeAuthorizationResponse(
                preparationState = preparationState,
                credentialPresentation = CredentialPresentation.DCQLPresentation(
                    presentationRequest = dcqlRequest,
                    credentialQuerySubmissions = badMatches
                ),
            ).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .submissionRequirementsValidationResult.isSuccess.shouldBeFalse()
        }

        "mdoc dcql: presenting correct credentials yields valid submission validation result" {
            issueAndStorePlainJwt(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, it.mdlScheme)

            val dcqlRequest = CredentialPresentationRequestBuilder(
                RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, ISO_MDOC)
            ).toDCQLRequest().shouldNotBeNull()

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(dcqlRequest),
                creationOptions = CreationOptions.Query("https://example.com")
            ).getOrThrow().url

            val preparationState = it.holderOid4vp.startAuthorizationResponsePreparation(authnRequest).getOrThrow()

            val goodMatches = it.holderAgent
                .matchPresentationRequestAgainstCredentialStore(dcqlRequest).getOrThrow()
                .shouldBeInstanceOf<DCQLMatchingResult<SubjectCredentialStore.StoreEntry>>()
                .matchingResult.credentialQueryMatches

            val authnResponse = it.holderOid4vp.finalizeAuthorizationResponse(
                preparationState = preparationState,
                credentialPresentation = CredentialPresentation.DCQLPresentation(
                    presentationRequest = dcqlRequest,
                    credentialQuerySubmissions = goodMatches
                ),
            ).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .submissionRequirementsValidationResult.isSuccess.shouldBeTrue()
        }

        "presentation of multiple credentials with different formats in one request/response" {
            issueAndStorePlainJwt(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, it.mdlScheme)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(CredentialPresentationRequestBuilder(
                    RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, PLAIN_JWT),
                    RequestOptionsCredential(it.mdlScheme, ISO_MDOC)
                ).toDCQLRequest(),),
                creationOptions = CreationOptions.Query("https://example.com")
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.shouldHaveSize(2)
        }

        "presentation of multiple SD-JWT credentials in one request/response" {
            issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial, it.euPidSdJwtScheme)
            issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

            val requestOptions = OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    RequestOptionsCredential(
                        credentialScheme = ConstantIndex.AtomicAttribute2023,
                        representation = SD_JWT,
                        attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_DATE_OF_BIRTH))
                    ),
                    RequestOptionsCredential(
                        credentialScheme = it.euPidSdJwtScheme,
                        representation = SD_JWT,
                        attributePaths = setOf(
                            DCQLClaimsPathPointer(EuPidSdJwtDataElements.FAMILY_NAME),
                            DCQLClaimsPathPointer(EuPidSdJwtDataElements.GIVEN_NAME)
                        ),
                    )
                ).toDCQLRequest(),
            )

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = requestOptions,
                creationOptions = CreationOptions.Query("https://example.com")
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            val groupedResult = it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }

            groupedResult.size shouldBe 2
            groupedResult.forEach { result ->
                result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
                result.reconstructedJsonObject.entries.shouldNotBeEmpty()
                when (result.verifiableCredentialSdJwt.verifiableCredentialType) {
                    EU_PID_SD_JWT_VCT -> {
                        result.reconstructedJsonObject[EuPidSdJwtDataElements.FAMILY_NAME].shouldNotBeNull()
                        result.reconstructedJsonObject[EuPidSdJwtDataElements.GIVEN_NAME].shouldNotBeNull()
                    }

                    ConstantIndex.AtomicAttribute2023.sdJwtType -> {
                        result.reconstructedJsonObject[CLAIM_DATE_OF_BIRTH].shouldNotBeNull()
                    }

                    else -> {
                        fail("Unexpected SD-JWT type: ${result.verifiableCredentialSdJwt.verifiableCredentialType}")
                    }
                }
            }
        }
    }
}



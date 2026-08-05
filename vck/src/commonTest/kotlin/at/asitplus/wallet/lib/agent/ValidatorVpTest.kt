package at.asitplus.wallet.lib.agent

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications: According to the W3C Verifiable Credential Data Model 1.1 https://www.w3.org/TR/vc-data-model-1.1/#jwt-encoding,
 * "iss MUST represent the issuer property of a verifiable credential or the holder property of a verifiable presentation."
 * So in this case the issuer should be the wallet holder, represented by it's DID.
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLJwtVcCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLJwtVcCredentialQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.issueAndStorePlainJwt
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialPresentation.DCQLPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.VerifiablePresentation
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.randomCwtOrJwtResolver
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking


val ValidatorVpTest by matrixSuite {

    val singularDcqlPresentation = DCQLPresentation(
        CredentialPresentationRequest.DCQLRequest(
            DCQLQuery(
                credentials = DCQLCredentialQueryList(
                    DCQLJwtVcCredentialQuery(
                        id = DCQLCredentialQueryIdentifier(uuid4().toString()),
                        meta = DCQLJwtVcCredentialMetadataAndValidityConstraints(
                            typeValues = nonEmptyListOf(listOfNotNull(ConstantIndex.AtomicAttribute2023.vcType))
                        ),
                    )
                )
            )
        ),
        credentialQuerySubmissions = null,
    )

    fixture {
        runBlocking {
            val holderCredentialStore = InMemorySubjectCredentialStore()
            val holderKeyMaterial = EphemeralKeyWithoutCert()
            val issuerCredentialStore = InMemoryIssuerCredentialStore()

            val issuer = IssuerAgent(
                issuerCredentialStore = issuerCredentialStore,
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            )

            val statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)

            val validator = ValidatorVcJws(
                validator = Validator(
                    tokenStatusResolver = randomCwtOrJwtResolver(statusListIssuer)
                )
            )
            val holder = HolderAgent(
                keyMaterial = holderKeyMaterial,
                subjectCredentialStore = holderCredentialStore,
                validatorVcJws = validator,
            ).also {
                issueAndStorePlainJwt(it, holderKeyMaterial, issuer)
            }
            object {
                val issuer = issuer
                val holderCredentialStore = holderCredentialStore
                val issuerCredentialStore = issuerCredentialStore
                val validator = validator

                val holder = holder
                val verifiablePresentationFactory = VerifiablePresentationFactory(holderKeyMaterial)
                val holderSignVp = SignJwt<VerifiablePresentationJws>(holderKeyMaterial, JwsHeaderCertOrJwk())
                val verifierId = "urn:${uuid4()}"
                val verifier = NonceChallengeVerifier(
                    verifierId = verifierId,
                    verifier = VerifierAgent(
                        identifier = verifierId,
                        validatorVcJws = validator,
                    ),
                )
            }
        }
    } - {

        "correct challenge in VP leads to Success" {
            val request = it.verifier.createPresentationRequest()
            val presentationParameters = it.holder.createPresentation(
                request = request,
                credentialPresentation = singularDcqlPresentation,
            ).getOrNull().shouldBeInstanceOf<PresentationResponseParameters.DCQLParameters>()

            val vp = presentationParameters.verifiablePresentations.values.first().first()
                .shouldBeInstanceOf<CreatePresentationResult.VpJws>()
            it.verifier.verifyPresentationVcJwt(vp.jwsSigned.shouldNotBeNull()).getOrThrow()
        }

        "Presentation of VC from different holder is detected" {
            val request = it.verifier.createPresentationRequest()
            val otherHolderKeyMaterial = EphemeralKeyWithoutCert()
            val otherHolder = HolderAgent(otherHolderKeyMaterial)
            issueAndStorePlainJwt(otherHolder, otherHolderKeyMaterial, it.issuer)
            val holderVc = otherHolder.getCredentials()
                .shouldNotBeNull()
                .shouldBeSingleton()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
            val vp = it.verifiablePresentationFactory.createVcPresentation(
                holderVc,
                request,
            ).shouldBeInstanceOf<CreatePresentationResult.VpJws>()

            it.verifier.verifyPresentationVcJwt(vp.jwsSigned.shouldNotBeNull()).getOrThrow().also {
                it.vp.freshVerifiableCredentials.shouldBeEmpty()
                it.vp.notVerifiablyFreshVerifiableCredentials.shouldBeEmpty()
                it.vp.invalidVerifiableCredentials.shouldBe(holderVc.map { it.vcSerialized })
            }
        }

        "wrong challenge in VP leads to error" {
            val presentationParameters = it.holder.createPresentation(
                request = PresentationRequestParameters(nonce = "challenge", audience = it.verifierId),
                credentialPresentation = singularDcqlPresentation,
            ).getOrNull().shouldBeInstanceOf<PresentationResponseParameters.DCQLParameters>()

            val vp = presentationParameters.verifiablePresentations.values.firstOrNull()?.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.VpJws>()
            shouldThrowAny {
                it.verifier.verifyPresentationVcJwt(vp.jwsSigned.shouldNotBeNull()).getOrThrow()
            }
        }

        "wrong audience in VP leads to error" {
            val request = it.verifier.createPresentationRequest()
            val presentationParameters = it.holder.createPresentation(
                request = PresentationRequestParameters(nonce = request.nonce, audience = "keyId"),
                credentialPresentation = singularDcqlPresentation,
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DCQLParameters>()

            val vp = presentationParameters.verifiablePresentations.values.first().first()
                .shouldBeInstanceOf<CreatePresentationResult.VpJws>()
            shouldThrowAny {
                it.verifier.verifyPresentationVcJwt(vp.jwsSigned.shouldNotBeNull()).getOrThrow()
            }
        }

        "valid parsed presentation should separate revoked and valid credentials" {
            val request = it.verifier.createPresentationRequest()
            val presentationResults = it.holder.createPresentation(
                request = request,
                credentialPresentation = singularDcqlPresentation,
            ).getOrNull().shouldBeInstanceOf<PresentationResponseParameters.DCQLParameters>()

            val vp = presentationResults.verifiablePresentations.values.first().first()
                .shouldBeInstanceOf<CreatePresentationResult.VpJws>()
            it.holderCredentialStore.getCredentials().getOrThrow()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
                .map { it.vc }
                .forEach { vcjws ->
                    it.issuerCredentialStore.setStatus(
                        timePeriod = FixedTimePeriodProvider.timePeriod,
                        index = vcjws.vc.credentialStatus.shouldBeInstanceOf<StatusListInfo>().index,
                        status = TokenStatus.Invalid,
                    ) shouldBe true
                }

            it.verifier.verifyPresentationVcJwt(vp.jwsSigned.shouldNotBeNull()).getOrThrow().also {
                it.shouldBeInstanceOf<VerifyPresentationResult.Success>()
                it.vp.freshVerifiableCredentials.shouldBeEmpty()
            }
            it.holderCredentialStore.getCredentials().getOrThrow()
                .shouldHaveSize(1)
        }

        "Manually created and presentation with jwkThumbprint is valid" {
            val request = it.verifier.createPresentationRequest()
            val credentials = it.holderCredentialStore.getCredentials().getOrThrow()
            val validCredentials = credentials
                .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
                .filter { storeEntry ->
                    it.validator.checkRevocationStatus(storeEntry.vc) !is TokenStatusValidationResult.Invalid
                }
                .map { it.vcSerialized }
            (validCredentials.isEmpty()) shouldBe false

            val vp = VerifiablePresentation(validCredentials)
            val vpSerialized = vp.toJws(
                challenge = request.nonce,
                issuerId = it.holder.keyMaterial.jsonWebKey.jwkThumbprint,
                audienceId = request.audience,
            )
            val vpJws = it.holderSignVp(
                JwsContentTypeConstants.JWT,
                vpSerialized,
                VerifiablePresentationJws.serializer()
            ).getOrThrow()

            it.verifier.verifyPresentationVcJwt(vpJws).getOrThrow()
                .shouldBeInstanceOf<VerifyPresentationResult.Success>()
        }

        "Manually created and presentation with did is valid" {
            val request = it.verifier.createPresentationRequest()
            val credentials = it.holderCredentialStore.getCredentials().getOrThrow()
            val validCredentials = credentials
                .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
                .filter { storeEntry ->
                    it.validator.checkRevocationStatus(storeEntry.vc) !is TokenStatusValidationResult.Invalid
                }
                .map { it.vcSerialized }
            (validCredentials.isEmpty()) shouldBe false

            val vp = VerifiablePresentation(validCredentials)
            val vpSerialized = vp.toJws(
                challenge = request.nonce,
                issuerId = it.holder.keyMaterial.jsonWebKey.didEncoded!!,
                audienceId = request.audience,
            )
            val vpJws = it.holderSignVp(
                JwsContentTypeConstants.JWT,
                vpSerialized,
                VerifiablePresentationJws.serializer()
            ).getOrThrow()

            it.verifier.verifyPresentationVcJwt(vpJws).getOrThrow()
                .shouldBeInstanceOf<VerifyPresentationResult.Success>()
        }

        "Wrong jwtId in VP is not valid" {
            val request = it.verifier.createPresentationRequest()
            val credentials = it.holderCredentialStore.getCredentials().getOrThrow()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
            val vp = VerifiablePresentation(credentials.map { it.vcSerialized })
            val vpSerialized = VerifiablePresentationJws(
                vp = vp,
                challenge = request.nonce,
                issuer = it.holder.keyMaterial.publicKey.didEncoded,
                audience = request.audience,
                jwtId = "wrong_jwtId",
            )
            val vpJws = it.holderSignVp(
                JwsContentTypeConstants.JWT,
                vpSerialized,
                VerifiablePresentationJws.serializer()
            ).getOrThrow()

            shouldThrowAny {
                it.verifier.verifyPresentationVcJwt(vpJws).getOrThrow()
            }
        }

        "Wrong type in VP is not valid" {
            val request = it.verifier.createPresentationRequest()
            val credentials = it.holderCredentialStore.getCredentials().getOrThrow()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
            val vp = VerifiablePresentation(
                id = "urn:uuid:${uuid4()}",
                type = "wrong_type",
                verifiableCredential = credentials.map { it.vcSerialized }
            )

            val vpSerialized = vp.toJws(
                challenge = request.nonce,
                issuerId = it.holder.keyMaterial.publicKey.didEncoded,
                audienceId = request.audience,
            )
            val vpJws = it.holderSignVp(
                JwsContentTypeConstants.JWT,
                vpSerialized,
                VerifiablePresentationJws.serializer()
            ).getOrThrow()

            shouldThrowAny {
                it.verifier.verifyPresentationVcJwt(vpJws).getOrThrow()
            }
        }
    }
}

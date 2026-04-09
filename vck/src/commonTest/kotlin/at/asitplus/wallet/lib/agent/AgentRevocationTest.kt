package at.asitplus.wallet.lib.agent

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

import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.FixedTimePeriodProvider.timePeriod
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.StatusListCwt
import at.asitplus.wallet.lib.data.StatusListJwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication.primitives.StatusListTokenMediaType
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.toJsonElement
import at.asitplus.wallet.lib.extensions.toView
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.AssertionErrorBuilder.Companion.fail
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

val AgentRevocationTest by testSuite {

    withFixtureGenerator(suspend {
        val issuerCredentialStore = InMemoryIssuerCredentialStore()
        val expectedRevokedIndexes = issuerCredentialStore.revokeRandomCredentials()
        object {
            val issuerCredentialStore = issuerCredentialStore
            val expectedRevokedIndexes = expectedRevokedIndexes
            val issuer = IssuerAgent(
                issuerCredentialStore = issuerCredentialStore,
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            )
            val statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
            val verifierKeyMaterial = EphemeralKeyWithoutCert()

        }
    }) - {

        "revocation list should contain indices of revoked credential" {
            val statusList = it.statusListIssuer.issueStatusListJwt()
                .shouldNotBeNull().payload.revocationList.shouldBeInstanceOf<StatusList>()

            verifyStatusList(statusList, it.expectedRevokedIndexes)
        }

        "aggregation should contain links if statuses have been set" {
            it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.verifierKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    PLAIN_JWT,
                ).getOrThrow()
            ).getOrElse {
                fail("no issued credentials")
            }
            it.issuerCredentialStore.revokeCredentialsWithIndexes(listOf(0U))

            val statusListAggregation = it.statusListIssuer.provideStatusListAggregation()
            statusListAggregation.statusLists.size should { it >= 1 }
        }

        "issued jwt should have same status list as provided token when asking for jwt" {
            it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.verifierKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    PLAIN_JWT,
                ).getOrThrow()
            ).getOrElse {
                fail("no issued credentials")
            }
            it.issuerCredentialStore.revokeCredentialsWithIndexes(listOf(0U))

            val timestamp = Clock.System.now()
            val issuedToken = it.statusListIssuer.issueStatusListJwt(timestamp)
            val (type, providedToken) = it.statusListIssuer.provideStatusListToken(
                acceptedContentTypes = listOf(StatusListTokenMediaType.Jwt),
                time = timestamp,
            )
            providedToken.shouldBeInstanceOf<StatusListJwt>()
            providedToken.shouldBeInstanceOf<StatusListJwt>().apply {
                value.payload.revocationList.shouldBeInstanceOf<StatusList>() shouldBe issuedToken.payload.revocationList
            }
        }

        "issued cwt should have same status list as provided token when asking for cwt" {
            it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.verifierKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    PLAIN_JWT,
                ).getOrThrow()
            ).getOrElse {
                fail("no issued credentials")
            }
            it.issuerCredentialStore.revokeCredentialsWithIndexes(listOf(0U))

            val timestamp = Clock.System.now()
            val issuedToken = it.statusListIssuer.issueStatusListJwt(timestamp)
            val (type, providedToken) = it.statusListIssuer.provideStatusListToken(
                acceptedContentTypes = listOf(StatusListTokenMediaType.Cwt),
                time = timestamp,
            )
            providedToken.shouldBeInstanceOf<StatusListCwt>()
                .parsedPayload.getOrThrow().revocationList shouldBe issuedToken.payload.revocationList
        }


        "revocation credential should be valid" {
            it.statusListIssuer.issueStatusListJwt().apply {
                shouldNotBeNull()
                VerifyJwsObject().invoke(this.jws).getOrThrow()
            }
            it.statusListIssuer.issueStatusListCwt().apply {
                shouldNotBeNull()
                payload.shouldNotBeNull().encodeToString(Base16Strict).lowercase().apply {
                    shouldContain("636c7374") // text(3) "lst"
                    shouldNotContain("d818") // tagged item (24) as payload
                }
                VerifyCoseSignature<ByteArray>().invoke(this, byteArrayOf(), null).isSuccess shouldBe true
            }
        }

        "credentials should contain status information" {
            val result = it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.verifierKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    PLAIN_JWT,
                ).getOrThrow()
            ).getOrElse {
                fail("no issued credentials")
            }.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

            ValidatorVcJws().verifyVcJws(result.signedVcJws, it.verifierKeyMaterial.publicKey).getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessJwt>()
                .jws.vc.credentialStatus
                .shouldNotBeNull()
                .shouldBeInstanceOf<StatusListInfo>()
                .index.shouldNotBeNull()
        }

        "encoding to a known value works" {
            val issuerCredentialStore = InMemoryIssuerCredentialStore()
            val statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
            val expectedRevokedIndexes: List<ULong> = listOf(1U, 2U, 4U, 6U, 7U, 9U, 10U, 12U, 13U, 14U)
            issuerCredentialStore.revokeCredentialsWithIndexes(expectedRevokedIndexes)

            val revocationList = statusListIssuer.buildRevocationList(timePeriod).shouldNotBeNull()

            verifyStatusList(revocationList.shouldBeInstanceOf<StatusList>(), expectedRevokedIndexes)
        }

        "decoding a known value works" {
            val expectedRevokedIndexes: List<ULong> = listOf(1U, 2U, 4U, 6U, 7U, 9U, 10U, 12U, 13U, 14U)

            val revocationList =
                Json.decodeFromString<StatusList>("""{"lst": "eJy7VgYAAiQBTQ==", "bits": 1}""")

            verifyStatusList(revocationList, expectedRevokedIndexes)
        }

        "ISO_MDOC credential can carry IdentifierList status info" {
            val issuedCredential = it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.verifierKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    revocationKind = RevocationList.Kind.IDENTIFIER_LIST,
                ).getOrThrow()
            ).getOrElse {
                fail("no issued credentials")
            }.shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()

            issuedCredential.mdocIdentifierListInfo().uri.string shouldContain "/identifier/"
        }

        "IdentifierList token should contain revoked ISO_MDOC identifier" {
            val issuedCredential = it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.verifierKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    revocationKind = RevocationList.Kind.IDENTIFIER_LIST,
                ).getOrThrow()
            ).getOrElse {
                fail("no issued credentials")
            }.shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()
            val statusInfo = issuedCredential.mdocIdentifierListInfo()

            it.statusListIssuer.revokeCredentialByIdentifier(timePeriod, statusInfo.identifier) shouldBe true

            val payload = StatusListCwt(
                value = it.statusListIssuer.issueStatusListCwt(kind = RevocationList.Kind.IDENTIFIER_LIST),
                resolvedAt = Clock.System.now(),
            ).parsedPayload.getOrThrow()

            val identifierList = payload.revocationList.shouldBeInstanceOf<IdentifierList>()
            identifierList.identifiers.keys.any {
                it.value.contentEquals(statusInfo.identifier)
            } shouldBe true
            payload.subject shouldBe statusInfo.uri
        }

        "revokeCredentialByIdentifier should return false for unknown identifier" {
            it.statusListIssuer.revokeCredentialByIdentifier(timePeriod, Random.nextBytes(16)) shouldBe false
        }

        "identifier list JWT should not be issued" {
            runCatching {
                it.statusListIssuer.issueStatusListJwt(kind = RevocationList.Kind.IDENTIFIER_LIST)
            }.isFailure shouldBe true
        }

        "identifier list aggregation should contain identifier URLs" {
            val aggregation = it.statusListIssuer.provideIdentifierListAggregation()
            aggregation.statusLists.map { uri -> uri.string }.any { it.contains("/identifier/") } shouldBe true
        }
    }
}

private fun Issuer.IssuedCredential.Iso.mdocIdentifierListInfo(): IdentifierListInfo =
    issuerSigned.issuerAuth.payload.shouldNotBeNull().status.shouldNotBeNull().shouldBeInstanceOf<IdentifierListInfo>()

private fun verifyStatusList(statusList: StatusList, expectedRevokedIndexes: List<ULong>) {
    val expectedRevocationStatuses = MutableList(expectedRevokedIndexes.max().toInt() + 1) {
        TokenStatus.Valid
    }
    expectedRevokedIndexes.forEach {
        expectedRevocationStatuses[it.toInt()] = TokenStatus.Invalid
    }
    expectedRevocationStatuses.forEachIndexed { index, it ->
        statusList.toView()[index.toULong()] shouldBe it
    }
}

private suspend fun InMemoryIssuerCredentialStore.revokeCredentialsWithIndexes(revokedIndexes: List<ULong>) {
    val cred = AtomicAttribute2023("sub", "name", "value", "text").toJsonElement()
    val issuanceDate = Clock.System.now()
    val expirationDate = issuanceDate + 60.seconds
    for (i in 1..16) {
        val reference = createStoredCredentialReference(
            CredentialToBeIssued.VcJwt(
                subject = cred,
                expiration = expirationDate,
                scheme = ConstantIndex.AtomicAttribute2023,
                subjectPublicKey = EphemeralKeyWithoutCert().publicKey,
                userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
            ),
            timePeriod
        ).getOrThrow()
        val revListIndex = reference.statusListIndex
        if (revokedIndexes.contains(revListIndex)) {
            setStatus(timePeriod, revListIndex, TokenStatus.Invalid)
        }
    }
}

private suspend fun InMemoryIssuerCredentialStore.revokeRandomCredentials(): List<ULong> {
    val expectedRevocationList = mutableListOf<ULong>()
    val cred = AtomicAttribute2023("sub", "name", "value", "text").toJsonElement()
    val issuanceDate = Clock.System.now()
    val expirationDate = issuanceDate + 60.seconds
    for (i in 1..256) {
        val revListIndex = createStoredCredentialReference(
            CredentialToBeIssued.VcJwt(
                subject = cred,
                expiration = expirationDate,
                scheme = ConstantIndex.AtomicAttribute2023,
                subjectPublicKey = EphemeralKeyWithoutCert().publicKey,
                userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
            ),
            timePeriod
        ).getOrThrow().statusListIndex
        if (Random.nextBoolean()) {
            expectedRevocationList += revListIndex
            setStatus(timePeriod, revListIndex, TokenStatus.Invalid)
        }
    }
    return expectedRevocationList.toList()
}

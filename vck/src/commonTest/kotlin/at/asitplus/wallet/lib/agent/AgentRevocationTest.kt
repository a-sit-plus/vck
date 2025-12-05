package at.asitplus.wallet.lib.agent

import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.FixedTimePeriodProvider.timePeriod
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.StatusListCwt
import at.asitplus.wallet.lib.data.StatusListJwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication.primitives.StatusListTokenMediaType
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.extensions.toView
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.AssertionErrorBuilder.Companion.fail
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
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
            val statusListJwt = it.statusListIssuer.issueStatusListJwt()
            statusListJwt.shouldNotBeNull()

            val statusList = statusListJwt.payload.statusList

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
            providedToken.value.payload.statusList shouldBe issuedToken.payload.statusList
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
            providedToken.value.payload!!.statusList shouldBe issuedToken.payload.statusList
        }


        "revocation credential should be valid" {
            it.statusListIssuer.issueStatusListJwt().also {
                it.shouldNotBeNull()
                VerifyJwsObject().invoke(it).getOrThrow()
            }
            it.statusListIssuer.issueStatusListCwt().also {
                it.shouldNotBeNull()
                VerifyCoseSignature<StatusListTokenPayload>().invoke(it, byteArrayOf(), null).isSuccess shouldBe true
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
            }
            result.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

            val vcJws = ValidatorVcJws().verifyVcJws(result.signedVcJws, it.verifierKeyMaterial.publicKey)
            vcJws.shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessJwt>()
            val credentialStatus = vcJws.jws.vc.credentialStatus
            credentialStatus.shouldNotBeNull()
            credentialStatus.statusList.shouldNotBeNull().index.shouldNotBeNull()
        }

        "encoding to a known value works" {
            val issuerCredentialStore = InMemoryIssuerCredentialStore()
            val statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
            val expectedRevokedIndexes: List<ULong> = listOf(1U, 2U, 4U, 6U, 7U, 9U, 10U, 12U, 13U, 14U)
            issuerCredentialStore.revokeCredentialsWithIndexes(expectedRevokedIndexes)

            val revocationList = statusListIssuer.buildStatusList(timePeriod)
            revocationList.shouldNotBeNull()

            verifyStatusList(revocationList, expectedRevokedIndexes)
        }

        "decoding a known value works" {
            val expectedRevokedIndexes: List<ULong> = listOf(1U, 2U, 4U, 6U, 7U, 9U, 10U, 12U, 13U, 14U)

            val revocationList =
                Json.decodeFromString<StatusList>("""{"lst": "eJy7VgYAAiQBTQ==", "bits": 1}""")

            verifyStatusList(revocationList, expectedRevokedIndexes)
        }
    }
}

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

private suspend fun IssuerCredentialStore.revokeCredentialsWithIndexes(revokedIndexes: List<ULong>) {
    val cred = AtomicAttribute2023("sub", "name", "value", "text")
    val issuanceDate = Clock.System.now()
    val expirationDate = issuanceDate + 60.seconds
    for (i in 1..16) {
        val reference = createStatusListIndex(
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

private suspend fun IssuerCredentialStore.revokeRandomCredentials(): List<ULong> {
    val expectedRevocationList = mutableListOf<ULong>()
    val cred = AtomicAttribute2023("sub", "name", "value", "text")
    val issuanceDate = Clock.System.now()
    val expirationDate = issuanceDate + 60.seconds
    for (i in 1..256) {
        val revListIndex = createStatusListIndex(
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

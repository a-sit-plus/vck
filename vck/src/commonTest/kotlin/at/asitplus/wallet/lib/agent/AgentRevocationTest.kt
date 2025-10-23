package at.asitplus.wallet.lib.agent

import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.wallet.lib.agent.FixedTimePeriodProvider.timePeriod
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication.primitives.StatusListTokenMediaType
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.extensions.toView
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import de.infix.testBalloon.framework.TestConfig
import de.infix.testBalloon.framework.aroundEach
import de.infix.testBalloon.framework.testSuite
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

    lateinit var issuerCredentialStore: IssuerCredentialStore
    lateinit var verifierKeyMaterial: KeyMaterial
    lateinit var issuer: Issuer
    lateinit var statusListIssuer: StatusListIssuer
    lateinit var expectedRevokedIndexes: List<ULong>

    testConfig= TestConfig.aroundEach {
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        issuer = IssuerAgent(
            issuerCredentialStore = issuerCredentialStore,
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        )
        statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
        verifierKeyMaterial = EphemeralKeyWithoutCert()
        expectedRevokedIndexes = issuerCredentialStore.revokeRandomCredentials()
        it()
    }

    "revocation list should contain indices of revoked credential" {
        val statusListJwt = statusListIssuer.issueStatusListJwt()
        statusListJwt.shouldNotBeNull()

        val statusList = statusListJwt.payload.statusList

        verifyStatusList(statusList, expectedRevokedIndexes)
    }

    "issuer as token status provider" - {
        "aggregation" - {
            "should contain links if statuses have been set" {
                issuer.issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        verifierKeyMaterial.publicKey,
                        ConstantIndex.AtomicAttribute2023,
                        PLAIN_JWT,
                    ).getOrThrow()
                ).getOrElse {
                    fail("no issued credentials")
                }
                issuerCredentialStore.revokeCredentialsWithIndexes(listOf(0U))

                val statusListAggregation = statusListIssuer.provideStatusListAggregation()
                statusListAggregation.statusLists.size should { it >= 1 }
            }
        }

        "issued jwt should have same status list as provided token when asking for jwt" {
            issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    verifierKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    PLAIN_JWT,
                ).getOrThrow()
            ).getOrElse {
                fail("no issued credentials")
            }
            issuerCredentialStore.revokeCredentialsWithIndexes(listOf(0U))

            val timestamp = Clock.System.now()
            val issuedToken = statusListIssuer.issueStatusListJwt(timestamp)
            val (type, providedToken) = statusListIssuer.provideStatusListToken(
                acceptedContentTypes = listOf(StatusListTokenMediaType.Jwt),
                time = timestamp,
            )
            providedToken.shouldBeInstanceOf<StatusListToken.StatusListJwt>()
            providedToken.value.payload.statusList shouldBe issuedToken.payload.statusList
        }

        "issued cwt should have same status list as provided token when asking for cwt" {
            issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    verifierKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    PLAIN_JWT,
                ).getOrThrow()
            ).getOrElse {
                fail("no issued credentials")
            }
            issuerCredentialStore.revokeCredentialsWithIndexes(listOf(0U))

            val timestamp = Clock.System.now()
            val issuedToken = statusListIssuer.issueStatusListJwt(timestamp)
            val (type, providedToken) = statusListIssuer.provideStatusListToken(
                acceptedContentTypes = listOf(StatusListTokenMediaType.Cwt),
                time = timestamp,
            )
            providedToken.shouldBeInstanceOf<StatusListToken.StatusListCwt>()
            providedToken.value.payload!!.statusList shouldBe issuedToken.payload.statusList
        }
    }

    "revocation credential should be valid" {
        statusListIssuer.issueStatusListJwt().also {
            it.shouldNotBeNull()
            VerifyJwsObject().invoke(it) shouldBe true
        }
        statusListIssuer.issueStatusListCwt().also {
            it.shouldNotBeNull()
            VerifyCoseSignature<StatusListTokenPayload>().invoke(it, byteArrayOf(), null).isSuccess shouldBe true
        }
    }

    "credentials should contain status information" {
        val result = issuer.issueCredential(
            DummyCredentialDataProvider.getCredential(
                verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                PLAIN_JWT,
            ).getOrThrow()
        ).getOrElse {
            fail("no issued credentials")
        }
        result.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

        val vcJws = ValidatorVcJws().verifyVcJws(result.signedVcJws, verifierKeyMaterial.publicKey)
        vcJws.shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessJwt>()
        val credentialStatus = vcJws.jws.vc.credentialStatus
        credentialStatus.shouldNotBeNull()
        credentialStatus.statusList.index.shouldNotBeNull()
    }

    "encoding to a known value works" {
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        issuer = IssuerAgent(
            issuerCredentialStore = issuerCredentialStore,
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        )
        statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
        expectedRevokedIndexes = listOf(1U, 2U, 4U, 6U, 7U, 9U, 10U, 12U, 13U, 14U)
        issuerCredentialStore.revokeCredentialsWithIndexes(expectedRevokedIndexes)

        val revocationList = statusListIssuer.buildStatusList(timePeriod)
        revocationList.shouldNotBeNull()

        verifyStatusList(revocationList, expectedRevokedIndexes)
    }

    "decoding a known value works" {
        expectedRevokedIndexes = listOf(1U, 2U, 4U, 6U, 7U, 9U, 10U, 12U, 13U, 14U)

        val revocationList =
            Json.decodeFromString<StatusList>("""{"lst": "eJy7VgYAAiQBTQ==", "bits": 1}""")

        verifyStatusList(revocationList, expectedRevokedIndexes)
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

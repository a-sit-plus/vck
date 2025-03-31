package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult.SuccessJwt
import at.asitplus.wallet.lib.cbor.DefaultVerifierCoseService
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication.primitives.StatusListTokenMediaType
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import com.benasher44.uuid.uuid4
import io.kotest.assertions.fail
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.datetime.Clock
import kotlinx.serialization.json.Json
import kotlin.random.Random
import kotlin.time.Duration.Companion.seconds

class AgentRevocationTest : FreeSpec({

    lateinit var issuerCredentialStore: IssuerCredentialStore
    lateinit var verifier: Verifier
    lateinit var verifierKeyMaterial: KeyMaterial
    lateinit var issuer: Issuer
    lateinit var expectedRevokedIndexes: List<Long>

    beforeEach {
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        issuer = IssuerAgent(EphemeralKeyWithoutCert(), issuerCredentialStore)
        verifierKeyMaterial = EphemeralKeyWithoutCert()
        verifier = VerifierAgent(identifier = "urn:${uuid4()}")
        expectedRevokedIndexes = issuerCredentialStore.revokeRandomCredentials()
    }

    "revocation list should contain indices of revoked credential" {
        val statusListJwt = issuer.issueStatusListJwt()
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
                        ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                    ).getOrThrow()
                ).getOrElse {
                    fail("no issued credentials")
                }
                issuerCredentialStore.revokeCredentialsWithIndexes(listOf(0))

                val statusListAggregation = issuer.provideStatusListAggregation()
                statusListAggregation.statusLists.size should {
                    it >= 1
                }
            }
        }

        "issued jwt should have same status list as provided token when asking for jwt" {
            issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    verifierKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).getOrThrow()
            ).getOrElse {
                fail("no issued credentials")
            }
            issuerCredentialStore.revokeCredentialsWithIndexes(listOf(0))

            val timestamp = Clock.System.now()
            val issuedToken = issuer.issueStatusListJwt(timestamp)
            val (type, providedToken) = issuer.provideStatusListToken(
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
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).getOrThrow()
            ).getOrElse {
                fail("no issued credentials")
            }
            issuerCredentialStore.revokeCredentialsWithIndexes(listOf(0))

            val timestamp = Clock.System.now()
            val issuedToken = issuer.issueStatusListJwt(timestamp)
            val (type, providedToken) = issuer.provideStatusListToken(
                acceptedContentTypes = listOf(StatusListTokenMediaType.Cwt),
                time = timestamp,
            )
            providedToken.shouldBeInstanceOf<StatusListToken.StatusListCwt>()
            providedToken.value.payload!!.statusList shouldBe issuedToken.payload.statusList
        }
    }

    "revocation credential should be valid" {
        issuer.issueStatusListJwt().also {
            it.shouldNotBeNull()
            VerifyJwsObject().invoke(it) shouldBe true
        }
        issuer.issueStatusListCwt().also {
            it.shouldNotBeNull()
            DefaultVerifierCoseService().verifyCose(it).isSuccess shouldBe true
        }
    }

    "credentials should contain status information" {
        val result = issuer.issueCredential(
            DummyCredentialDataProvider.getCredential(
                verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT,
            ).getOrThrow()
        ).getOrElse {
            fail("no issued credentials")
        }
        result.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

        val vcJws = Validator().verifyVcJws(result.vcJws, verifierKeyMaterial.publicKey)
        vcJws.shouldBeInstanceOf<SuccessJwt>()
        val credentialStatus = vcJws.jws.vc.credentialStatus
        credentialStatus.shouldNotBeNull()
        credentialStatus.statusList.index.shouldNotBeNull()
    }

    "encoding to a known value works" {
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        issuer = IssuerAgent(EphemeralKeyWithoutCert(), issuerCredentialStore)
        expectedRevokedIndexes = listOf(1, 2, 4, 6, 7, 9, 10, 12, 13, 14)
        issuerCredentialStore.revokeCredentialsWithIndexes(expectedRevokedIndexes)

        val revocationList = issuer.buildStatusList(FixedTimePeriodProvider.timePeriod)
        revocationList.shouldNotBeNull()

        verifyStatusList(revocationList, expectedRevokedIndexes)
    }

    "decoding a known value works" {
        expectedRevokedIndexes = listOf(1, 2, 4, 6, 7, 9, 10, 12, 13, 14)

        val revocationList =
            Json.decodeFromString<StatusList>("""{"lst": "eJy7VgYAAiQBTQ==", "bits": 1}""")

        verifyStatusList(revocationList, expectedRevokedIndexes)
    }
})


private fun verifyStatusList(statusList: StatusList, expectedRevokedIndexes: List<Long>) {
    val expectedRevocationStatuses = MutableList(expectedRevokedIndexes.max().toInt() + 1) {
        TokenStatus.Valid
    }
    expectedRevokedIndexes.forEach {
        expectedRevocationStatuses[it.toInt()] = TokenStatus.Invalid
    }
    expectedRevocationStatuses.forEachIndexed { index, it ->
        statusList.view[index.toULong()] shouldBe it
    }
}

private suspend fun IssuerCredentialStore.revokeCredentialsWithIndexes(revokedIndexes: List<Long>) {
    val cred = AtomicAttribute2023("sub", "name", "value", "text")
    val issuanceDate = Clock.System.now()
    val expirationDate = issuanceDate + 60.seconds
    for (i in 1..16) {
        val vcId = uuid4().toString()
        val revListIndex = storeGetNextIndex(
            credential = IssuerCredentialStore.Credential.VcJwt(
                vcId, cred, ConstantIndex.AtomicAttribute2023
            ),
            subjectPublicKey = EphemeralKeyWithoutCert().publicKey,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
            timePeriod = FixedTimePeriodProvider.timePeriod
        )!!
        if (revokedIndexes.contains(revListIndex)) {
            setStatus(
                vcId,
                status = TokenStatus.Invalid,
                FixedTimePeriodProvider.timePeriod,
            )
        }
    }
}

private suspend fun IssuerCredentialStore.revokeRandomCredentials(): MutableList<Long> {
    val expectedRevocationList = mutableListOf<Long>()
    val cred = AtomicAttribute2023("sub", "name", "value", "text")
    val issuanceDate = Clock.System.now()
    val expirationDate = issuanceDate + 60.seconds
    for (i in 1..256) {
        val vcId = uuid4().toString()
        val revListIndex = storeGetNextIndex(
            credential = IssuerCredentialStore.Credential.VcJwt(
                vcId, cred, ConstantIndex.AtomicAttribute2023
            ),
            subjectPublicKey = EphemeralKeyWithoutCert().publicKey,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
            timePeriod = FixedTimePeriodProvider.timePeriod
        )!!
        if (Random.nextBoolean()) {
            expectedRevocationList += revListIndex
            setStatus(
                vcId,
                status = TokenStatus.Invalid,
                FixedTimePeriodProvider.timePeriod,
            )
        }
    }
    return expectedRevocationList
}

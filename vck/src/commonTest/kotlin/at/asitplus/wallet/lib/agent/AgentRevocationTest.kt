package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.FixedTimePeriodProvider.timePeriod
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.StatusListCwt
import at.asitplus.wallet.lib.data.StatusListJwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
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
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json
import kotlin.random.Random
import kotlin.time.Clock

val AgentRevocationTest by testSuite {

    withFixtureGenerator(suspend {
        val issuerCredentialStore = InMemoryIssuerCredentialStore()
        val issuer = IssuerAgent(
            issuerCredentialStore = issuerCredentialStore,
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        )
        val verifierKeyMaterial = EphemeralKeyWithoutCert()

        object {
            val expectedRevokedIndexes: List<ULong> = listOf(1U, 2U, 4U, 6U, 7U, 9U, 10U, 12U, 13U, 14U)
            val issuer = issuer
            val issuerCredentialStore = issuerCredentialStore
            val statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
            val verifierKeyMaterial = verifierKeyMaterial
        }
    }) - {

        "revocation list should contain indices of revoked credential" {
            batchIssueCredentials(15, it.issuer, it.verifierKeyMaterial.publicKey)
            it.issuerCredentialStore.revokeCredentialsWithIndexes(it.expectedRevokedIndexes)
            val statusList = it.statusListIssuer.issueStatusListJwt()
                .shouldNotBeNull().payload.revocationList.shouldBeInstanceOf<StatusList>()

            verifyStatusList(statusList, it.expectedRevokedIndexes)
        }

        "aggregation should contain links if statuses have been set" {
            issueCredential(it.issuer, it.verifierKeyMaterial.publicKey)
            it.issuerCredentialStore.revokeCredentialsWithIndexes(listOf(0U))

            val statusListAggregation = it.statusListIssuer.provideStatusListAggregation()
            statusListAggregation.statusLists.size should { it >= 1 }
        }

        "issued jwt should have same status list as provided token when asking for jwt" {
            issueCredential(it.issuer, it.verifierKeyMaterial.publicKey)
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
            issueCredential(it.issuer, it.verifierKeyMaterial.publicKey)
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
                VerifyJwsObject().invoke(this).getOrThrow()
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
            val result = issueCredential(
                it.issuer,
                it.verifierKeyMaterial.publicKey
            ).shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

            ValidatorVcJws().verifyVcJws(result.signedVcJws, it.verifierKeyMaterial.publicKey)
                .shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessJwt>()
                .jws.vc.credentialStatus
                .shouldNotBeNull()
                .shouldBeInstanceOf<StatusListInfo>()
                .index.shouldNotBeNull()
        }

        "encoding to a known value works" {
            val expectedRevokedIndexes: List<ULong> = listOf(1U, 2U, 4U, 6U, 7U, 9U, 10U, 12U, 13U, 14U)
            batchIssueCredentials(15, it.issuer, it.verifierKeyMaterial.publicKey)
            it.issuerCredentialStore.revokeCredentialsWithIndexes(expectedRevokedIndexes)

            val revocationList = it.statusListIssuer.buildRevocationList(timePeriod).shouldNotBeNull()

            verifyStatusList(revocationList.shouldBeInstanceOf<StatusList>(), expectedRevokedIndexes)
        }

        "decoding a known value works" {
            val revocationList =
                Json.decodeFromString<StatusList>("""{"lst": "eJy7VgYAAiQBTQ==", "bits": 1}""")

            verifyStatusList(revocationList, it.expectedRevokedIndexes)
        }
    }
}

private suspend fun issueCredential(issuer: Issuer, publicKey: CryptoPublicKey) =
    issuer.issueCredential(
        DummyCredentialDataProvider.getCredential(
            publicKey,
            ConstantIndex.AtomicAttribute2023,
            PLAIN_JWT,
        ).getOrThrow()
    ).getOrElse {
        fail("no issued credentials")
    }

private suspend fun batchIssueCredentials(numCred: Int, issuer: Issuer, publicKey: CryptoPublicKey) =
    (0..<numCred).forEach { _ -> issueCredential(issuer, publicKey) }

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
    revokedIndexes.forEach { id ->
        setStatus(timePeriod, id, TokenStatus.Invalid)
    }
}

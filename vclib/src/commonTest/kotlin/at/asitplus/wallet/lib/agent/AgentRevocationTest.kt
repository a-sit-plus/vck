package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.KmmBitSet
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult.SuccessJwt
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.toBitSet
import com.benasher44.uuid.uuid4
import io.kotest.assertions.fail
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.component.base64.decodeBase64ToArray
import kotlinx.datetime.Clock
import kotlin.random.Random
import kotlin.time.Duration.Companion.seconds

class AgentRevocationTest : FreeSpec({

    lateinit var issuerCredentialStore: IssuerCredentialStore
    lateinit var verifier: Verifier
    lateinit var verifierCryptoService: CryptoService
    lateinit var issuer: Issuer
    lateinit var expectedRevokedIndexes: List<Long>

    beforeEach {
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        issuer = IssuerAgent.newDefaultInstance(
            cryptoService = DefaultCryptoService(),
            issuerCredentialStore = issuerCredentialStore,
            dataProvider = DummyCredentialDataProvider()
        )
        verifierCryptoService = DefaultCryptoService()
        verifier = VerifierAgent.newDefaultInstance(verifierCryptoService.identifier)
        expectedRevokedIndexes = issuerCredentialStore.revokeRandomCredentials()
    }

    "revocation list should contain indices of revoked credential" {
        val revocationList = issuer.buildRevocationList(FixedTimePeriodProvider.timePeriod)
        revocationList.shouldNotBeNull()
        val bitSetRevocationList = decodeRevocationList(revocationList)

        verifyBitSet(bitSetRevocationList, expectedRevokedIndexes)
    }

    "revocation credential should be valid" {
        val revocationCredential = issuer.issueRevocationListCredential(FixedTimePeriodProvider.timePeriod)
        revocationCredential.shouldNotBeNull()
        val vcJws = verifier.setRevocationList(revocationCredential)
        vcJws shouldBe true
    }

    "credentials should contain status information" {
        val result = issuer.issueCredential(
            subjectPublicKey = verifierCryptoService.toPublicKey(),
            attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
            representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT
        )
        if (result.failed.isNotEmpty()) fail("no issued credentials")

        result.successful.filterIsInstance<Issuer.IssuedCredential.VcJwt>().map { it.vcJws }.forEach {
            val vcJws = verifier.verifyVcJws(it)
            vcJws.shouldBeInstanceOf<SuccessJwt>()
            val credentialStatus = vcJws.jws.vc.credentialStatus
            credentialStatus.shouldNotBeNull()
            credentialStatus.index.shouldNotBeNull()
        }
    }

    "encoding to a known value works" {
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        issuer = IssuerAgent.newDefaultInstance(
            cryptoService = DefaultCryptoService(),
            issuerCredentialStore = issuerCredentialStore,
        )
        expectedRevokedIndexes = listOf(1, 2, 4, 6, 7, 9, 10, 12, 13, 14)
        issuerCredentialStore.revokeCredentialsWithIndexes(expectedRevokedIndexes)

        val revocationList = issuer.buildRevocationList(FixedTimePeriodProvider.timePeriod)
        revocationList.shouldNotBeNull()
        // This bitset 0110 1011 0110 1110 should result in "eJy7VgYAAiQBTQ=="
        // when using ZLIB Deflate and Base64 encoding
        revocationList shouldBe "eJy7VgYAAiQBTQ=="
        val bitSetRevocationList = decodeRevocationList(revocationList)

        verifyBitSet(bitSetRevocationList, expectedRevokedIndexes)
    }

    "decoding a known value works" {
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        issuer = IssuerAgent.newDefaultInstance(
            cryptoService = DefaultCryptoService(),
            issuerCredentialStore = issuerCredentialStore,
        )
        expectedRevokedIndexes = listOf(1, 2, 4, 6, 7, 9, 10, 12, 13, 14)
        issuerCredentialStore.revokeCredentialsWithIndexes(expectedRevokedIndexes)

        val revocationList = "eJy7VgYAAiQBTQ=="
        // Should result in this bitset: 0110 1011 0110 1110
        // i.e. exactly the expectedRevocationList from above
        val bitSetRevocationList = decodeRevocationList(revocationList)

        verifyBitSet(bitSetRevocationList, expectedRevokedIndexes)
    }

})

private fun decodeRevocationList(revocationList: String): KmmBitSet {
    val decodedBase64 = revocationList.decodeBase64ToArray()
    decodedBase64.shouldNotBeNull()
    val decompress = DefaultZlibService().decompress(decodedBase64)
    decompress.shouldNotBeNull()
    return decompress.toBitSet()
}

private fun verifyBitSet(bitSet: KmmBitSet, expectedRevokedIndexes: List<Long>) {
    var indexInBitSet: Long = bitSet.nextSetBit(0)
    while (indexInBitSet >= 0 && indexInBitSet < Int.MAX_VALUE) {
        expectedRevokedIndexes shouldContain indexInBitSet
        indexInBitSet = bitSet.nextSetBit(indexInBitSet + 1)
    }
    expectedRevokedIndexes.forEach { bitSet[it] shouldBe true }
}

private fun IssuerCredentialStore.revokeCredentialsWithIndexes(revokedIndexes: List<Long>) {
    val cred = AtomicAttribute2023("sub", "name", "value", "text")
    val issuanceDate = Clock.System.now()
    val expirationDate = issuanceDate + 60.seconds
    for (i in 1..16) {
        val vcId = uuid4().toString()
        val revListIndex =
            storeGetNextIndex(vcId, cred, issuanceDate, expirationDate, FixedTimePeriodProvider.timePeriod)!!
        if (revokedIndexes.contains(revListIndex)) {
            revoke(vcId, FixedTimePeriodProvider.timePeriod)
        }
    }
}

private fun IssuerCredentialStore.revokeRandomCredentials(): MutableList<Long> {
    val expectedRevocationList = mutableListOf<Long>()
    val cred = AtomicAttribute2023("sub", "name", "value", "text")
    val issuanceDate = Clock.System.now()
    val expirationDate = issuanceDate + 60.seconds
    for (i in 1..256) {
        val vcId = uuid4().toString()
        val revListIndex =
            storeGetNextIndex(vcId, cred, issuanceDate, expirationDate, FixedTimePeriodProvider.timePeriod)!!
        if (Random.nextBoolean()) {
            expectedRevocationList += revListIndex
            revoke(vcId, FixedTimePeriodProvider.timePeriod)
        }
    }
    return expectedRevocationList
}


package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.Companion.ATTRIBUTE_WITH_ATTACHMENT
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.SchemaIndex
import at.asitplus.wallet.lib.uuid4
import io.kotest.assertions.fail
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

class AgentTest : FreeSpec({

    lateinit var issuerCryptoService: CryptoService
    lateinit var holderCryptoService: CryptoService
    lateinit var verifierCryptoService: CryptoService
    lateinit var issuer: Issuer
    lateinit var holder: Holder
    lateinit var verifier: Verifier
    lateinit var issuerCredentialStore: IssuerCredentialStore
    lateinit var holderCredentialStore: SubjectCredentialStore
    lateinit var challenge: String

    beforeEach {
        issuerCryptoService = DefaultCryptoService()
        holderCryptoService = DefaultCryptoService()
        verifierCryptoService = DefaultCryptoService()
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        holderCredentialStore = InMemorySubjectCredentialStore()
        issuer = IssuerAgent.newDefaultInstance(
            cryptoService = issuerCryptoService,
            issuerCredentialStore = issuerCredentialStore,
            dataProvider = DummyCredentialDataProvider(),
        )
        holder = HolderAgent.newDefaultInstance(
            holderCryptoService,
            subjectCredentialStore = holderCredentialStore
        )
        verifier = VerifierAgent.newDefaultInstance(verifierCryptoService.keyId)
        challenge = uuid4()
    }

    "simple walk-through success" {
        val vcList =
            issuer.issueCredentials(holderCryptoService.keyId, AttributeIndex.genericAttributes)
        if (vcList.failed.isNotEmpty()) fail("no issued credentials")
        holder.storeCredentials(vcList.toStoreCredentialInput())

        val vp = holder.createPresentation(challenge, verifierCryptoService.keyId)
        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.Signed>()
        val verified = verifier.verifyPresentation(vp.jws, challenge)
        verified.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
    }

    "simple walk-through success with attachments" {
        val vcList = issuer.issueCredentials(
            holderCryptoService.keyId,
            listOf("${SchemaIndex.ATTR_GENERIC_PREFIX}/$ATTRIBUTE_WITH_ATTACHMENT")
        )
        vcList.successful.shouldNotBeEmpty()
        holder.storeCredentials(vcList.toStoreCredentialInput())
        holderCredentialStore.getAttachment(ATTRIBUTE_WITH_ATTACHMENT).getOrThrow().shouldNotBeNull()

        val vp = holder.createPresentation(challenge, verifierCryptoService.keyId)
        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.Signed>()
        val verified = verifier.verifyPresentation(vp.jws, challenge)
        verified.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
    }

    "wrong keyId in presentation leads to InvalidStructure" {
        val credentials =
            issuer.issueCredentials(holderCryptoService.keyId, AttributeIndex.genericAttributes)
        if (credentials.failed.isNotEmpty()) fail("no issued credentials")
        holder.storeCredentials(credentials.toStoreCredentialInput())

        val vp = holder.createPresentation(challenge, issuerCryptoService.keyId)
        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.Signed>()
        val result = verifier.verifyPresentation(vp.jws, challenge)
        result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }

    "revoked credentials must not be validated" {
        val credentials =
            issuer.issueCredentials(verifierCryptoService.keyId, AttributeIndex.genericAttributes)
        if (credentials.failed.isNotEmpty()) fail("no issued credentials")
        issuer.revokeCredentials(credentials.successful.map { it.vcJws }) shouldBe true

        val revocationListCredential = issuer.issueRevocationListCredential(FixedTimePeriodProvider.timePeriod)
        revocationListCredential.shouldNotBeNull()
        verifier.setRevocationList(revocationListCredential) shouldBe true

        credentials.successful.map { it.vcJws }.forEach {
            verifier.verifyVcJws(it).shouldBeInstanceOf<Verifier.VerifyCredentialResult.Revoked>()
        }
    }

    "building presentation with revoked credentials should not work" - {

        "when setting a revocation list before storing credentials" {
            val credentials =
                issuer.issueCredentials(holderCryptoService.keyId, AttributeIndex.genericAttributes)
            if (credentials.failed.isNotEmpty()) fail("no issued credentials")
            issuer.revokeCredentials(credentials.successful.map { it.vcJws }) shouldBe true
            val revocationListCredential = issuer.issueRevocationListCredential(FixedTimePeriodProvider.timePeriod)
            revocationListCredential.shouldNotBeNull()
            holder.setRevocationList(revocationListCredential) shouldBe true

            val storedCredentials = holder.storeCredentials(credentials.toStoreCredentialInput())
            storedCredentials.accepted.shouldBeEmpty()
            storedCredentials.rejected shouldHaveSize credentials.successful.size
            storedCredentials.notVerified.shouldBeEmpty()

            holder.createPresentation(challenge, verifierCryptoService.keyId) shouldBe null
        }

        "and when setting a revocation list after storing credentials" {
            val credentials =
                issuer.issueCredentials(holderCryptoService.keyId, AttributeIndex.genericAttributes)
            if (credentials.failed.isNotEmpty()) fail("no issued credentials")
            val storedCredentials = holder.storeCredentials(credentials.toStoreCredentialInput())
            storedCredentials.accepted shouldHaveSize credentials.successful.size
            storedCredentials.rejected.shouldBeEmpty()
            storedCredentials.notVerified.shouldBeEmpty()

            issuer.revokeCredentials(credentials.successful.map { it.vcJws }) shouldBe true
            val revocationListCredential = issuer.issueRevocationListCredential(FixedTimePeriodProvider.timePeriod)
            revocationListCredential.shouldNotBeNull()
            holder.setRevocationList(revocationListCredential) shouldBe true

            holder.createPresentation(challenge, verifierCryptoService.keyId) shouldBe null
        }
    }

    "getting credentials that have been stored by the holder" - {

        "when there are no credentials stored" {
            val holderCredentials = holder.getCredentials()
            holderCredentials.shouldNotBeNull()
            holderCredentials.shouldBeEmpty()
        }

        "when they are valid" - {
            val credentials =
                issuer.issueCredentials(holderCryptoService.keyId, AttributeIndex.genericAttributes)
            if (credentials.failed.isNotEmpty()) fail("no issued credentials")
            val storedCredentials = holder.storeCredentials(credentials.toStoreCredentialInput())
            storedCredentials.accepted shouldHaveSize credentials.successful.size
            storedCredentials.rejected.shouldBeEmpty()
            storedCredentials.notVerified.shouldBeEmpty()

            "without a revocation list set" {
                val holderCredentials = holder.getCredentials()
                holderCredentials.shouldNotBeNull()
                holderCredentials.forEach {
                    it.status.shouldBe(Validator.RevocationStatus.UNKNOWN)
                }
            }

            "with a revocation list set" {
                holder.setRevocationList(issuer.issueRevocationListCredential(FixedTimePeriodProvider.timePeriod)!!) shouldBe true
                val holderCredentials = holder.getCredentials()
                holderCredentials.shouldNotBeNull()
                holderCredentials.forEach {
                    it.status.shouldBe(Validator.RevocationStatus.VALID)
                }
            }
        }

        "when the issuer has revoked them" {
            val credentials =
                issuer.issueCredentials(holderCryptoService.keyId, AttributeIndex.genericAttributes)
            if (credentials.failed.isNotEmpty()) fail("no issued credentials")
            val storedCredentials = holder.storeCredentials(credentials.toStoreCredentialInput())
            storedCredentials.accepted shouldHaveSize credentials.successful.size
            storedCredentials.rejected.shouldBeEmpty()
            storedCredentials.notVerified.shouldBeEmpty()

            issuer.revokeCredentials(credentials.successful.map { it.vcJws }) shouldBe true
            val revocationListCredential = issuer.issueRevocationListCredential(FixedTimePeriodProvider.timePeriod)
            revocationListCredential.shouldNotBeNull()
            holder.setRevocationList(revocationListCredential) shouldBe true

            val holderCredentials = holder.getCredentials()
            holderCredentials.shouldNotBeNull()
            holderCredentials.forEach {
                it.status.shouldBe(Validator.RevocationStatus.REVOKED)
            }
        }
    }

    "building presentation without necessary credentials" {
        holder.createPresentation(challenge, verifierCryptoService.keyId) shouldBe null
    }

    "valid presentation is valid" {
        val credentials =
            issuer.issueCredentials(holderCryptoService.keyId, AttributeIndex.genericAttributes)
        if (credentials.failed.isNotEmpty()) fail("no issued credentials")
        holder.storeCredentials(credentials.toStoreCredentialInput())
        val vp = holder.createPresentation(challenge, verifierCryptoService.keyId)
        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.Signed>()

        val result = verifier.verifyPresentation(vp.jws, challenge)
        result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
        result.vp.revokedVerifiableCredentials.shouldBeEmpty()
        credentials.successful shouldHaveSize result.vp.verifiableCredentials.size
        verifier.verifyPresentationContainsAttributes(result.vp, AttributeIndex.genericAttributes) shouldBe true
    }

    "valid presentation is valid -- some other attributes revoked" {
        val credentials =
            issuer.issueCredentials(holderCryptoService.keyId, AttributeIndex.genericAttributes)
        if (credentials.failed.isNotEmpty()) fail("no issued credentials")
        holder.storeCredentials(credentials.toStoreCredentialInput())
        val vp = holder.createPresentation(challenge, verifierCryptoService.keyId)
        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.Signed>()

        val credentialsToRevoke =
            issuer.issueCredentials(issuerCryptoService.keyId, AttributeIndex.genericAttributes)
        if (credentialsToRevoke.failed.isNotEmpty()) fail("no issued credentials")
        issuer.revokeCredentials(credentialsToRevoke.successful.map { it.vcJws }) shouldBe true
        val revocationList = issuer.issueRevocationListCredential(FixedTimePeriodProvider.timePeriod)
        revocationList.shouldNotBeNull()
        verifier.setRevocationList(revocationList) shouldBe true

        val result = verifier.verifyPresentation(vp.jws, challenge)
        result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
    }

})

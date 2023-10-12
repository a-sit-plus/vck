package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.ConstantIndex
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf

class AgentSdJwtTest : FreeSpec({

    lateinit var issuer: Issuer
    lateinit var holder: Holder
    lateinit var verifier: Verifier
    lateinit var issuerCredentialStore: IssuerCredentialStore
    lateinit var holderCredentialStore: SubjectCredentialStore
    lateinit var challenge: String

    beforeEach {
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        holderCredentialStore = InMemorySubjectCredentialStore()
        issuer = IssuerAgent.newDefaultInstance(
            issuerCredentialStore = issuerCredentialStore,
            dataProvider = DummyCredentialDataProvider(),
        )
        holder = HolderAgent.newDefaultInstance(
            subjectCredentialStore = holderCredentialStore
        )
        verifier = VerifierAgent.newRandomInstance()
        challenge = uuid4().toString()
    }

    "simple walk-through success" {
        val vcList = issuer.issueCredentialWithTypes(
            holder.identifier,
            attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
            representation = ConstantIndex.CredentialRepresentation.SD_JWT,
        ).also {
            it.failed.shouldBeEmpty()
            it.successful.shouldNotBeEmpty()
            it.successful.forEach { println(it) }
        }

        holder.storeCredentials(vcList.toStoreCredentialInput()).also {
            it.acceptedSdJwt.shouldNotBeEmpty()
            it.notVerified.shouldBeEmpty()
            it.rejected.shouldBeEmpty()
            it.acceptedSdJwt.forEach { println(it) }
        }

        val vp = holder.createPresentation(challenge, verifier.identifier).also {
            it.shouldNotBeNull()
        }
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.SdJwt>()
        println("Presentation: " + vp.sdJwt)

        val verified = verifier.verifyPresentation(vp.sdJwt, challenge)
        verified.shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
    }

})

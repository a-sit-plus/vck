package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VerifiablePresentation
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsService
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking

class ValidatorVpTest : FreeSpec({

    lateinit var validator: Validator
    lateinit var issuer: Issuer
    lateinit var issuerCredentialStore: IssuerCredentialStore
    lateinit var holder: Holder
    lateinit var holderCredentialStore: SubjectCredentialStore
    lateinit var holderJwsService: JwsService
    lateinit var holderCryptoService: CryptoService
    lateinit var verifier: Verifier
    lateinit var challenge: String

    beforeEach {
        validator = Validator.newDefaultInstance(DefaultVerifierCryptoService())
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        issuer = IssuerAgent.newDefaultInstance(
            issuerCredentialStore = issuerCredentialStore,
            dataProvider = DummyCredentialDataProvider(),
        )
        holderCredentialStore = InMemorySubjectCredentialStore()
        holderCryptoService = DefaultCryptoService()
        holder = HolderAgent.newDefaultInstance(
            cryptoService = holderCryptoService,
            subjectCredentialStore = holderCredentialStore,
        )
        holderJwsService = DefaultJwsService(holderCryptoService)
        verifier = VerifierAgent.newRandomInstance()
        challenge = uuid4().toString()
        runBlocking {
            holder.storeCredentials(
                issuer.issueCredentialWithTypes(
                    holder.identifier,
                    listOf(ConstantIndex.AtomicAttribute2023.vcType)
                ).toStoreCredentialInput()
            )
        }
    }

    "correct challenge in VP leads to Success" {
        val vp = holder.createPresentation(challenge, verifier.identifier)

        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.Signed>()
        val result = verifier.verifyPresentation(vp.jws, challenge)
        result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
    }

    "wrong structure of VC is detected" {
        val holderCredentials = holder.getCredentials()
        holderCredentials.shouldNotBeNull()
        val holderVcSerialized = holderCredentials.map { it.vcSerialized }.map { it.reversed() }
        val vp = holder.createPresentation(holderVcSerialized, challenge, verifier.identifier)
        vp.shouldNotBeNull()

        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.Signed>()
        val result = verifier.verifyPresentation(vp.jws, challenge)
        result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
        result.vp.verifiableCredentials.shouldBeEmpty()
        result.vp.revokedVerifiableCredentials.shouldBeEmpty()
        result.vp.invalidVerifiableCredentials.shouldBe(holderVcSerialized)
    }

    "wrong challenge in VP leads to InvalidStructure" {
        val vp = holder.createPresentation("challenge", verifier.identifier)

        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.Signed>()
        val result = verifier.verifyPresentation(vp.jws, challenge)
        result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }

    "wrong audience in VP leads to InvalidStructure" {
        val vp = holder.createPresentation(challenge, "keyId")

        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.Signed>()
        val result = verifier.verifyPresentation(vp.jws, challenge)
        result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }

    "valid parsed presentation should separate revoked and valid credentials" {
        val vp = holder.createPresentation(challenge, verifier.identifier)

        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.Signed>()
        holderCredentialStore.getCredentials().getOrThrow().map { it.vc }
            .forEach {
                issuerCredentialStore.revoke(it.vc.id, FixedTimePeriodProvider.timePeriod) shouldBe true
            }
        val revocationList = issuer.issueRevocationListCredential(FixedTimePeriodProvider.timePeriod)
        revocationList.shouldNotBeNull()
        verifier.setRevocationList(revocationList)

        val result = verifier.verifyPresentation(vp.jws, challenge)

        result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
        result.vp.verifiableCredentials.shouldBeEmpty()
        holderCredentialStore.getCredentials().getOrThrow()
            .shouldHaveSize(result.vp.revokedVerifiableCredentials.size)
    }

    "Manually created and valid presentation is valid" {
        val credentials = holderCredentialStore.getCredentials().getOrThrow()
        val validCredentials = credentials
            .filter { validator.checkRevocationStatus(it.vc) != Validator.RevocationStatus.REVOKED }
            .map { it.vcSerialized }
        (validCredentials.isEmpty()) shouldBe false

        val vp = VerifiablePresentation(validCredentials.toTypedArray())
        val vpSerialized = vp.toJws(
            challenge = challenge,
            issuerId = holder.identifier,
            audienceId = verifier.identifier,
        ).serialize()
        val jwsPayload = vpSerialized.encodeToByteArray()
        val vpJws = holderJwsService.createSignedJwt(JwsContentTypeConstants.JWT, jwsPayload)
        vpJws.shouldNotBeNull()

        verifier.verifyPresentation(vpJws, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
    }

    "Wrong issuer in VP is not valid" {
        val credentials =
            holderCredentialStore.getCredentials().getOrThrow().map { it.vcSerialized }

        val vp = VerifiablePresentation(credentials.toTypedArray())
        val vpSerialized = VerifiablePresentationJws(
            vp = vp,
            challenge = challenge,
            issuer = verifier.identifier,
            audience = verifier.identifier,
            jwtId = vp.id,
        ).serialize()
        val jwsPayload = vpSerialized.encodeToByteArray()
        val vpJws = holderJwsService.createSignedJwt(JwsContentTypeConstants.JWT, jwsPayload)
        vpJws.shouldNotBeNull()

        verifier.verifyPresentation(vpJws, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }

    "Wrong jwtId in VP is not valid" {
        val credentials =
            holderCredentialStore.getCredentials().getOrThrow().map { it.vcSerialized }
        val vp = VerifiablePresentation(credentials.toTypedArray())
        val vpSerialized = VerifiablePresentationJws(
            vp = vp,
            challenge = challenge,
            issuer = holder.identifier,
            audience = verifier.identifier,
            jwtId = "wrong_jwtId",
        ).serialize()
        val jwsPayload = vpSerialized.encodeToByteArray()
        val vpJws = holderJwsService.createSignedJwt(JwsContentTypeConstants.JWT, jwsPayload)
        vpJws.shouldNotBeNull()

        verifier.verifyPresentation(vpJws, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }

    "Wrong type in VP is not valid" {
        val credentials =
            holderCredentialStore.getCredentials().getOrThrow().map { it.vcSerialized }
        val vp = VerifiablePresentation(
            id = "urn:uuid:${uuid4()}",
            type = "wrong_type",
            verifiableCredential = credentials.toTypedArray()
        )
        val vpSerialized = vp.toJws(
            challenge = challenge,
            issuerId = holder.identifier,
            audienceId = verifier.identifier,
        ).serialize()
        val jwsPayload = vpSerialized.encodeToByteArray()
        val vpJws = holderJwsService.createSignedJwt(JwsContentTypeConstants.JWT, jwsPayload)
        vpJws.shouldNotBeNull()

        verifier.verifyPresentation(vpJws, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }
})

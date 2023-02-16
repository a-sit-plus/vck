package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.AtomicAttributeCredential
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.CredentialStatus
import at.asitplus.wallet.lib.data.VerifiableCredential
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsContentType
import at.asitplus.wallet.lib.jws.JwsHeader
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.jws.JwsSigned
import at.asitplus.wallet.lib.nameHack
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.core.spec.style.scopes.ContainerScope
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.component.base64.Base64
import io.matthewnelson.component.base64.encodeBase64
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

class ValidatorVcTest : FreeSpec() {

    lateinit var issuer: Issuer
    lateinit var issuerCredentialStore: IssuerCredentialStore
    lateinit var issuerJwsService: JwsService
    lateinit var issuerCryptoService: CryptoService
    lateinit var verifier: Verifier
    lateinit var verifierCryptoService: CryptoService

    private val dataProvider: IssuerCredentialDataProvider = DummyCredentialDataProvider()
    private val revocationListUrl: String = "https://wallet.a-sit.at/backend/credentials/status/1"

    init {
        beforeEach {
            issuerCredentialStore = InMemoryIssuerCredentialStore()
            issuerCryptoService = DefaultCryptoService()
            issuer = IssuerAgent.newDefaultInstance(
                cryptoService = issuerCryptoService,
                issuerCredentialStore = issuerCredentialStore,
            )
            issuerJwsService = DefaultJwsService(issuerCryptoService)
            verifierCryptoService = DefaultCryptoService()
            verifier = VerifierAgent.newDefaultInstance(verifierCryptoService.keyId)
        }

        "credentials are valid for" {
            issuer.issueCredentials(verifierCryptoService.keyId, AttributeIndex.genericAttributes)
                .successful.map { it.vcJws }
                .forEach {
                    verifier.verifyVcJws(it).shouldBeInstanceOf<Verifier.VerifyCredentialResult.Success>()
                }
        }

        "revoked credentials are not valid" {
            issuer.issueCredentials(verifierCryptoService.keyId, AttributeIndex.genericAttributes)
                .successful
                .map { it.vcJws }
                .map { it to verifier.verifyVcJws(it) }.forEach {
                    val value = it.second
                    value.shouldBeInstanceOf<Verifier.VerifyCredentialResult.Success>()
                    issuerCredentialStore.revoke(value.jws.vc.id, FixedTimePeriodProvider.timePeriod) shouldBe true
                    val revocationListCredential =
                        issuer.issueRevocationListCredential(FixedTimePeriodProvider.timePeriod)
                    revocationListCredential.shouldNotBeNull()
                    verifier.setRevocationList(revocationListCredential)
                    verifier.verifyVcJws(it.first)
                        .shouldBeInstanceOf<Verifier.VerifyCredentialResult.Revoked>()

                    val defaultValidator = Validator.newDefaultInstance(DefaultVerifierCryptoService())
                    defaultValidator.setRevocationList(revocationListCredential) shouldBe true
                    defaultValidator.checkRevocationStatus(value.jws.vc.credentialStatus!!.index) shouldBe Validator.RevocationStatus.REVOKED
                }
        }

        "wrong subject keyId is not be valid" {
            issuer.issueCredentials(uuid4().toString(), AttributeIndex.genericAttributes)
                .successful.map { it.vcJws }.forEach {
                    verifier.verifyVcJws(it)
                        .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                }
        }

        "credential with invalid JWS format is not valid" {
            issuer.issueCredentials(verifierCryptoService.keyId, AttributeIndex.genericAttributes)
                .successful.map { it.vcJws }
                .map { it.replaceFirstChar { "f" } }.forEach {
                    verifier.verifyVcJws(it)
                        .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                }
        }

        "Manually created and valid credential is valid" - {
            withData(nameFn = ::vcName, AttributeIndex.genericAttributes) {
                it.let { dataProvider.getClaim(verifierCryptoService.keyId, it).getOrThrow() }
                    .let { issueCredential(it) }
                    .let { wrapVcInJws(it) }
                    .let { signJws(it) }
                    ?.let {
                        verifier.verifyVcJws(it).shouldBeInstanceOf<Verifier.VerifyCredentialResult.Success>()
                    }
            }
        }

        "Wrong key ends in wrong signature is not valid" - {
            withData(nameFn = ::vcName, AttributeIndex.genericAttributes) {
                it.let { dataProvider.getClaim(verifierCryptoService.keyId, it).getOrThrow() }
                    .let { issueCredential(it) }
                    .let { wrapVcInJws(it) }
                    .let { wrapVcInJwsWrongKey(it) }
                    ?.let {
                        verifier.verifyVcJws(it)
                            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Invalid sub in credential is not valid" - {
            withData(nameFn = ::vcName, AttributeIndex.genericAttributes) {
                it.let { dataProvider.getClaim(verifierCryptoService.keyId, it).getOrThrow() }
                    .let { issueCredential(it) }
                    .let { wrapVcInJws(it, subject = "vc.id") }
                    .let { signJws(it) }
                    ?.let {
                        verifier.verifyVcJws(it)
                            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Invalid issuer in credential is not valid" - {
            withData(nameFn = ::vcName, AttributeIndex.genericAttributes) {
                it.let { dataProvider.getClaim(verifierCryptoService.keyId, it).getOrThrow() }
                    .let { issueCredential(it) }
                    .let { wrapVcInJws(it, issuer = "vc.issuer") }
                    .let { signJws(it) }?.let {
                        verifier.verifyVcJws(it)
                            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Invalid jwtId in credential is not valid" - {
            withData(nameFn = ::vcName, AttributeIndex.genericAttributes) {
                it.let { dataProvider.getClaim(verifierCryptoService.keyId, it).getOrThrow() }
                    .let { issueCredential(it) }
                    .let { wrapVcInJws(it, jwtId = "vc.jwtId") }
                    .let { signJws(it) }
                    ?.let {
                        verifier.verifyVcJws(it)
                            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Invalid type in credential is not valid" - {
            withData(nameFn = ::vcName, AttributeIndex.genericAttributes) {
                it.let { dataProvider.getClaim(verifierCryptoService.keyId, it).getOrThrow() }
                    .let { issueCredential(it) }
                    .also { it.type[0] = "fakeCredential" }
                    .let { wrapVcInJws(it) }
                    .let { signJws(it) }
                    ?.let {
                        verifier.verifyVcJws(it)
                            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Invalid expiration in credential is not valid" - {
            withData(nameFn = ::vcName, AttributeIndex.genericAttributes) {
                it.let { dataProvider.getClaim(verifierCryptoService.keyId, it).getOrThrow() }
                    .let { issueCredential(it, expirationDate = Clock.System.now() - 1.hours) }
                    .let {
                        VerifiableCredentialJws(
                            vc = it,
                            subject = verifierCryptoService.keyId,
                            notBefore = it.issuanceDate,
                            issuer = it.issuer,
                            expiration = Clock.System.now() + 1.hours,
                            jwtId = it.id
                        )
                    }
                    .let { signJws(it) }
                    ?.let {
                        verifier.verifyVcJws(it)
                            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "No expiration date is valid" - {
            withData(nameFn = ::vcName, AttributeIndex.genericAttributes) {
                it.let { dataProvider.getClaim(verifierCryptoService.keyId, it).getOrThrow() }
                    .let { issueCredential(it, expirationDate = null) }
                    .let { wrapVcInJws(it) }
                    .let { signJws(it) }
                    ?.let {
                        verifier.verifyVcJws(it).shouldBeInstanceOf<Verifier.VerifyCredentialResult.Success>()
                    }
            }
        }

        "Invalid jws-expiration in credential is not valid" - {
            withData(nameFn = ::vcName, AttributeIndex.genericAttributes) {
                it.let { dataProvider.getClaim(verifierCryptoService.keyId, it).getOrThrow() }
                    .let {
                        issueCredential(it, expirationDate = Clock.System.now() + 1.hours)
                    }
                    .let {
                        wrapVcInJws(it, expirationDate = Clock.System.now() - 1.hours)
                    }
                    .let { signJws(it) }
                    ?.let {
                        verifier.verifyVcJws(it)
                            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Expiration not matching in credential is not valid" - {
            withData(nameFn = ::vcName, AttributeIndex.genericAttributes) {
                it.let { dataProvider.getClaim(verifierCryptoService.keyId, it).getOrThrow() }
                    .let {
                        issueCredential(it, expirationDate = Clock.System.now() + 1.hours)
                    }
                    .let {
                        wrapVcInJws(it, expirationDate = Clock.System.now() + 2.hours)
                    }
                    .let { signJws(it) }
                    ?.let {
                        verifier.verifyVcJws(it)
                            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Invalid NotBefore in credential is not valid" - {
            withData(nameFn = ::vcName, AttributeIndex.genericAttributes) {
                it.let { dataProvider.getClaim(verifierCryptoService.keyId, it).getOrThrow() }
                    .let { issueCredential(it) }
                    .let {
                        wrapVcInJws(it, issuanceDate = Clock.System.now() + 2.hours)
                    }
                    .let { signJws(it) }
                    ?.let {
                        verifier.verifyVcJws(it)
                            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Invalid issuance date in credential is not valid" - {
            withData(nameFn = ::vcName, AttributeIndex.genericAttributes) {
                it.let { dataProvider.getClaim(verifierCryptoService.keyId, it).getOrThrow() }
                    .let {
                        issueCredential(it, issuanceDate = Clock.System.now() + 1.hours)
                    }
                    .let { wrapVcInJws(it) }
                    .let { signJws(it) }
                    ?.let {
                        verifier.verifyVcJws(it)
                            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Issuance date and not before not matching is not valid" - {
            withData(nameFn = ::vcName, AttributeIndex.genericAttributes) {
                it.let { dataProvider.getClaim(verifierCryptoService.keyId, it).getOrThrow() }
                    .let {
                        issueCredential(it, issuanceDate = Clock.System.now() - 1.hours)
                    }
                    .let { wrapVcInJws(it, issuanceDate = Clock.System.now()) }
                    .let { signJws(it) }
                    ?.let {
                        verifier.verifyVcJws(it)
                            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }
    }

    private fun issueCredential(
        credential: IssuerCredentialDataProvider.CredentialToBeIssued,
        issuanceDate: Instant = Clock.System.now(),
        expirationDate: Instant? = Clock.System.now() + 60.seconds
    ): VerifiableCredential {
        val sub = credential.subject
        sub as AtomicAttributeCredential
        val vcId = "urn:uuid:${uuid4()}"
        val exp = expirationDate ?: (Clock.System.now() + 60.seconds)
        val statusListIndex =
            issuerCredentialStore.storeGetNextIndex(vcId, sub, issuanceDate, exp, FixedTimePeriodProvider.timePeriod)!!
        val credentialStatus = CredentialStatus(revocationListUrl, statusListIndex)
        return VerifiableCredential(
            id = vcId,
            issuer = issuerCryptoService.keyId,
            credentialStatus = credentialStatus,
            credentialSubject = sub,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
        )
    }

    private fun wrapVcInJws(
        it: VerifiableCredential,
        subject: String = verifierCryptoService.keyId,
        issuer: String = it.issuer,
        jwtId: String = it.id,
        issuanceDate: Instant = it.issuanceDate,
        expirationDate: Instant? = it.expirationDate,
    ) = VerifiableCredentialJws(
        vc = it,
        subject = subject,
        notBefore = issuanceDate,
        issuer = issuer,
        expiration = expirationDate,
        jwtId = jwtId
    )

    private suspend fun signJws(vcJws: VerifiableCredentialJws): String? {
        val vcSerialized = vcJws.serialize()
        val jwsPayload = vcSerialized.encodeToByteArray()
        return issuerJwsService.createSignedJwt(JwsContentType.JWT, jwsPayload)
    }

    private suspend fun wrapVcInJwsWrongKey(vcJws: VerifiableCredentialJws): String? {
        val jwsHeader = JwsHeader(
            verifierCryptoService.jwsAlgorithm,
            verifierCryptoService.keyId,
            JwsContentType.JWT
        )
        val jwsPayload = vcJws.serialize().encodeToByteArray()
        val signatureInput =
            jwsHeader.serialize().encodeToByteArray().encodeBase64(Base64.UrlSafe(pad = false)) +
                    "." + jwsPayload.encodeBase64(Base64.UrlSafe(pad = false))
        val signatureInputBytes = signatureInput.encodeToByteArray()
        val signature = issuerCryptoService.sign(signatureInputBytes)
            .getOrElse { return null }
        return JwsSigned(jwsHeader, jwsPayload, signature, signatureInput).serialize()
    }

}

private fun ContainerScope.vcName(it: String) = nameHack(it.substring(it.lastIndexOf('/') + 1))


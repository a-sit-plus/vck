package at.asitplus.wallet.lib.agent

import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import at.asitplus.crypto.datatypes.jws.JwsAlgorithm
import at.asitplus.crypto.datatypes.jws.JwsHeader
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.wallet.lib.data.*
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsService
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

class ValidatorVcTest : FreeSpec() {

    private lateinit var issuer: Issuer
    private lateinit var issuerCredentialStore: IssuerCredentialStore
    private lateinit var issuerJwsService: JwsService
    private lateinit var issuerCryptoService: CryptoService
    private lateinit var verifier: Verifier
    private lateinit var verifierCryptoService: CryptoService

    private val dataProvider: IssuerCredentialDataProvider = DummyCredentialDataProvider()
    private val revocationListUrl: String = "https://wallet.a-sit.at/backend/credentials/status/1"

    init {
        beforeEach {
            issuerCredentialStore = InMemoryIssuerCredentialStore()
            issuerCryptoService = DefaultCryptoService()
            issuer = IssuerAgent(
                issuerCryptoService,
                issuerCredentialStore,
            )
            issuerJwsService = DefaultJwsService(issuerCryptoService)
            verifierCryptoService = DefaultCryptoService()
            verifier = VerifierAgent(verifierCryptoService.publicKey)
        }

        "credentials are valid for" {
            issuer.issueCredential(
                subjectPublicKey = verifierCryptoService.publicKey,
                attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT
            ).successful.filterIsInstance<Issuer.IssuedCredential.VcJwt>().map { it.vcJws }
                .forEach {
                    verifier.verifyVcJws(it).shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessJwt>()
                }
        }

        "revoked credentials are not valid" {
            issuer.issueCredential(
                subjectPublicKey = verifierCryptoService.publicKey,
                attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT
            ).successful
                .filterIsInstance<Issuer.IssuedCredential.VcJwt>()
                .map { it.vcJws }
                .map { it to verifier.verifyVcJws(it) }.forEach {
                    val value = it.second
                    value.shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessJwt>()
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
            issuer.issueCredential(
                subjectPublicKey = DefaultCryptoService().publicKey,
                attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT
            ).successful
                .filterIsInstance<Issuer.IssuedCredential.VcJwt>()
                .map { it.vcJws }.forEach {
                    verifier.verifyVcJws(it)
                        .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                }
        }

        "credential with invalid JWS format is not valid" {
            issuer.issueCredential(
                subjectPublicKey = verifierCryptoService.publicKey,
                attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT
            ).successful
                .filterIsInstance<Issuer.IssuedCredential.VcJwt>()
                .map { it.vcJws }
                .map { it.replaceFirstChar { "f" } }.forEach {
                    verifier.verifyVcJws(it)
                        .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                }
        }

        "Manually created and valid credential is valid" - {
            withData(
                nameFn = ::credentialNameFn,
                dataProvider.getCredential(
                    verifierCryptoService.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT
                ).getOrThrow()
            ) {
                issueCredential(it)
                    .let { wrapVcInJws(it) }
                    .let { signJws(it) }
                    ?.let {
                        verifier.verifyVcJws(it).shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessJwt>()
                    }
            }
        }

        "Wrong key ends in wrong signature is not valid" - {
            withData(
                nameFn = ::credentialNameFn,
                dataProvider.getCredential(
                    verifierCryptoService.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT
                ).getOrThrow()
            ) {
                issueCredential(it)
                    .let { wrapVcInJws(it) }
                    .let { wrapVcInJwsWrongKey(it) }
                    ?.let {
                        verifier.verifyVcJws(it)
                            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Invalid sub in credential is not valid" - {
            withData(
                nameFn = ::credentialNameFn,
                dataProvider.getCredential(
                    verifierCryptoService.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT
                ).getOrThrow()
            ) {
                issueCredential(it)
                    .let { wrapVcInJws(it, subject = "vc.id") }
                    .let { signJws(it) }
                    ?.let {
                        verifier.verifyVcJws(it)
                            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Invalid issuer in credential is not valid" - {
            withData(
                nameFn = ::credentialNameFn,
                dataProvider.getCredential(
                    verifierCryptoService.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT
                ).getOrThrow()
            ) {
                issueCredential(it)
                    .let { wrapVcInJws(it, issuer = "vc.issuer") }
                    .let { signJws(it) }?.let {
                        verifier.verifyVcJws(it)
                            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Invalid jwtId in credential is not valid" - {
            withData(
                nameFn = ::credentialNameFn,
                dataProvider.getCredential(
                    verifierCryptoService.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT
                ).getOrThrow()
            ) {
                issueCredential(it)
                    .let { wrapVcInJws(it, jwtId = "vc.jwtId") }
                    .let { signJws(it) }
                    ?.let {
                        verifier.verifyVcJws(it)
                            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Invalid expiration in credential is not valid" - {
            withData(
                nameFn = ::credentialNameFn,
                dataProvider.getCredential(
                    verifierCryptoService.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT
                ).getOrThrow()
            ) {
                issueCredential(it, expirationDate = Clock.System.now() - 1.hours)
                    .let {
                        VerifiableCredentialJws(
                            vc = it,
                            subject = verifier.publicKey.didEncoded,
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
            withData(
                nameFn = ::credentialNameFn,
                dataProvider.getCredential(
                    verifierCryptoService.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT
                ).getOrThrow()
            ) {
                issueCredential(it, expirationDate = null)
                    .let { wrapVcInJws(it) }
                    .let { signJws(it) }
                    ?.let {
                        verifier.verifyVcJws(it).shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessJwt>()
                    }
            }
        }

        "Invalid jws-expiration in credential is not valid" - {
            withData(
                nameFn = ::credentialNameFn,
                dataProvider.getCredential(
                    verifierCryptoService.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT
                ).getOrThrow()
            ) {
                issueCredential(it, expirationDate = Clock.System.now() + 1.hours)
                    .let { wrapVcInJws(it, expirationDate = Clock.System.now() - 1.hours) }
                    .let { signJws(it) }
                    ?.let {
                        verifier.verifyVcJws(it)
                            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Expiration not matching in credential is not valid" - {
            withData(
                nameFn = ::credentialNameFn,
                dataProvider.getCredential(
                    verifierCryptoService.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT
                ).getOrThrow()
            ) {
                it.let { issueCredential(it, expirationDate = Clock.System.now() + 1.hours) }
                    .let { wrapVcInJws(it, expirationDate = Clock.System.now() + 2.hours) }
                    .let { signJws(it) }
                    ?.let {
                        verifier.verifyVcJws(it)
                            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Invalid NotBefore in credential is not valid" - {
            withData(
                nameFn = ::credentialNameFn,
                dataProvider.getCredential(
                    verifierCryptoService.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT
                ).getOrThrow()
            ) {
                it.let { issueCredential(it) }
                    .let { wrapVcInJws(it, issuanceDate = Clock.System.now() + 2.hours) }
                    .let { signJws(it) }
                    ?.let {
                        verifier.verifyVcJws(it)
                            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Invalid issuance date in credential is not valid" - {
            withData(
                nameFn = ::credentialNameFn,
                dataProvider.getCredential(
                    verifierCryptoService.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT
                ).getOrThrow()
            ) {
                issueCredential(it, issuanceDate = Clock.System.now() + 1.hours)
                    .let { wrapVcInJws(it) }
                    .let { signJws(it) }
                    ?.let {
                        verifier.verifyVcJws(it)
                            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Issuance date and not before not matching is not valid" - {
            withData(
                nameFn = ::credentialNameFn,
                dataProvider.getCredential(
                    verifierCryptoService.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT
                ).getOrThrow()
            ) {
                issueCredential(it, issuanceDate = Clock.System.now() - 1.hours)
                    .let { wrapVcInJws(it, issuanceDate = Clock.System.now()) }
                    .let { signJws(it) }
                    ?.let {
                        verifier.verifyVcJws(it)
                            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }
    }

    private fun credentialNameFn(it: CredentialToBeIssued): String =
        when (it) {
            is CredentialToBeIssued.Iso -> (it::class.simpleName ?: "Iso") + "-" +
                    it.issuerSignedItems.hashCode()
            is CredentialToBeIssued.VcJwt -> (it::class.simpleName ?: "VcJwt") + "-" +
                    it.subject.hashCode()
            is CredentialToBeIssued.VcSd -> (it::class.simpleName ?: "VcSd") + "-" +
                    it.claims.hashCode()
        }

    private fun issueCredential(
        credential: CredentialToBeIssued,
        issuanceDate: Instant = Clock.System.now(),
        expirationDate: Instant? = Clock.System.now() + 60.seconds,
        type: String = ConstantIndex.AtomicAttribute2023.vcType,
    ): VerifiableCredential {
        credential.shouldBeInstanceOf<CredentialToBeIssued.VcJwt>()
        val sub = credential.subject
        sub as AtomicAttribute2023
        val vcId = "urn:uuid:${uuid4()}"
        val exp = expirationDate ?: (Clock.System.now() + 60.seconds)
        val statusListIndex = issuerCredentialStore.storeGetNextIndex(
            credential = IssuerCredentialStore.Credential.VcJwt(vcId, sub, ConstantIndex.AtomicAttribute2023),
            subjectPublicKey = issuerCryptoService.publicKey,
            issuanceDate = issuanceDate,
            expirationDate = exp,
            timePeriod = FixedTimePeriodProvider.timePeriod
        )!!
        val credentialStatus = CredentialStatus(revocationListUrl, statusListIndex)
        return VerifiableCredential(
            id = vcId,
            issuer = issuer.publicKey.identifier,
            credentialStatus = credentialStatus,
            credentialSubject = sub,
            credentialType = type,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
        )
    }

    private fun wrapVcInJws(
        it: VerifiableCredential,
        subject: String = verifier.publicKey.didEncoded,
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

    private suspend fun signJws(vcJws: VerifiableCredentialJws): String {
        val vcSerialized = vcJws.serialize()
        val jwsPayload = vcSerialized.encodeToByteArray()
        return issuerJwsService.createSignedJwt(JwsContentTypeConstants.JWT, jwsPayload).getOrThrow().serialize()
    }

    private suspend fun wrapVcInJwsWrongKey(vcJws: VerifiableCredentialJws): String? {
        val jwsHeader = JwsHeader(
            algorithm = JwsAlgorithm.ES256,
            keyId = verifier.publicKey.didEncoded,
            type = JwsContentTypeConstants.JWT
        )
        val jwsPayload = vcJws.serialize().encodeToByteArray()
        val signatureInput =
            jwsHeader.serialize().encodeToByteArray().encodeToString(Base64UrlStrict) +
                    "." + jwsPayload.encodeToString(Base64UrlStrict)
        val signatureInputBytes = signatureInput.encodeToByteArray()
        val signature = issuerCryptoService.sign(signatureInputBytes)
            .getOrElse { return null }
        return JwsSigned(jwsHeader, jwsPayload, signature, signatureInput).serialize()
    }

}

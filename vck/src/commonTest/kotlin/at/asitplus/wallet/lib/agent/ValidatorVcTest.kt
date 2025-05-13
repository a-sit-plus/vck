package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.supreme.signature
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult
import at.asitplus.wallet.lib.agent.validation.TokenStatusValidationResult
import at.asitplus.wallet.lib.data.*
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderKeyId
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlin.random.Random
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds


class ValidatorVcTest : FreeSpec() {

    private lateinit var issuer: Issuer
    private lateinit var issuerCredentialStore: IssuerCredentialStore
    private lateinit var issuerSignVc: SignJwtFun<VerifiableCredentialJws>
    private lateinit var issuerKeyMaterial: KeyMaterial
    private lateinit var verifierKeyMaterial: KeyMaterial
    private lateinit var validator: Validator

    private val revocationListUrl: String = "https://wallet.a-sit.at/backend/credentials/status/1"

    init {
        beforeEach {
            validator = Validator(
                resolveStatusListToken = {
                    if (Random.nextBoolean()) StatusListToken.StatusListJwt(
                        issuer.issueStatusListJwt(),
                        resolvedAt = Clock.System.now(),
                    ) else {
                        StatusListToken.StatusListCwt(
                            issuer.issueStatusListCwt(),
                            resolvedAt = Clock.System.now(),
                        )
                    }
                },
            )
            issuerCredentialStore = InMemoryIssuerCredentialStore()
            issuerKeyMaterial = EphemeralKeyWithoutCert()
            issuer = IssuerAgent(
                issuerKeyMaterial,
                validator = validator,
                issuerCredentialStore = issuerCredentialStore,
            )
            issuerSignVc = SignJwt(issuerKeyMaterial, JwsHeaderKeyId())
            verifierKeyMaterial = EphemeralKeyWithoutCert()
        }

        "credentials are valid for" {
            val credential = issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    verifierKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
            credential.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

            validator.verifyVcJws(credential.vcJws, verifierKeyMaterial.publicKey)
                .shouldBeInstanceOf<VerifyCredentialResult.SuccessJwt>()
        }

        "revoked credentials are not valid" {
            val credential = issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    verifierKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
            credential.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

            val value = validator.verifyVcJws(credential.vcJws, verifierKeyMaterial.publicKey)
                .shouldBeInstanceOf<VerifyCredentialResult.SuccessJwt>()
            issuerCredentialStore.setStatus(
                value.jws.vc.id,
                status = TokenStatus.Invalid,
                FixedTimePeriodProvider.timePeriod,
            ) shouldBe true

            validator.verifyVcJws(credential.vcJws, verifierKeyMaterial.publicKey)
                .shouldBeInstanceOf<VerifyCredentialResult.SuccessJwt>()

            validator.checkRevocationStatus(value.jws)
                .shouldBeInstanceOf<TokenStatusValidationResult.Invalid>()
                .tokenStatus shouldBe TokenStatus.Invalid
        }

        "wrong subject keyId is not be valid" {
            val credential = issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    EphemeralKeyWithoutCert().publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
            credential.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

            validator.verifyVcJws(credential.vcJws, verifierKeyMaterial.publicKey)
                .shouldBeInstanceOf<VerifyCredentialResult.ValidationError>()
        }

        "credential with invalid JWS format is not valid" {
            val credential = issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    verifierKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
            credential.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

            validator.verifyVcJws(credential.vcJws.replaceFirstChar { "f" }, verifierKeyMaterial.publicKey)
                .shouldBeInstanceOf<VerifyCredentialResult.InvalidStructure>()
        }

        "Manually created and valid credential is valid" {
            DummyCredentialDataProvider.getCredential(
                verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT
            ).getOrThrow().let {
                issueCredential(it)
                    .let { wrapVcInJws(it) }
                    .let { signJws(it) }
                    .let {
                        validator.verifyVcJws(it, verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.SuccessJwt>()
                    }
            }
        }

        "Wrong key ends in wrong signature is not valid" {
            DummyCredentialDataProvider.getCredential(
                verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT
            ).getOrThrow().let {
                issueCredential(it)
                    .let { wrapVcInJws(it) }
                    .let { wrapVcInJwsWrongKey(it) }
                    .let {
                        validator.verifyVcJws(it, verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Invalid sub in credential is not valid" {
            DummyCredentialDataProvider.getCredential(
                verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT
            ).getOrThrow().let {
                issueCredential(it)
                    .let { wrapVcInJws(it, subject = "vc.id") }
                    .let { signJws(it) }
                    .let {
                        validator.verifyVcJws(it, verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Invalid issuer in credential is not valid" {
            DummyCredentialDataProvider.getCredential(
                verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT
            ).getOrThrow().let {
                issueCredential(it)
                    .let { wrapVcInJws(it, issuer = "vc.issuer") }
                    .let { signJws(it) }.let {
                        validator.verifyVcJws(it, verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Invalid jwtId in credential is not valid" {
            DummyCredentialDataProvider.getCredential(
                verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT
            ).getOrThrow().let {
                issueCredential(it)
                    .let { wrapVcInJws(it, jwtId = "vc.jwtId") }
                    .let { signJws(it) }
                    .let {
                        validator.verifyVcJws(it, verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Invalid expiration in credential is not valid" {
            DummyCredentialDataProvider.getCredential(
                verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT
            ).getOrThrow().let {
                issueCredential(it, expirationDate = Clock.System.now() - 1.hours)
                    .let {
                        VerifiableCredentialJws(
                            vc = it,
                            subject = "urn:${uuid4()}",
                            notBefore = it.issuanceDate,
                            issuer = it.issuer,
                            expiration = Clock.System.now() + 1.hours,
                            jwtId = it.id
                        )
                    }
                    .let { signJws(it) }
                    .let {
                        validator.verifyVcJws(it, verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "No expiration date is valid" {
            DummyCredentialDataProvider.getCredential(
                verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT
            ).getOrThrow().let {
                issueCredential(it, expirationDate = null)
                    .let { wrapVcInJws(it) }
                    .let { signJws(it) }
                    .let {
                        validator.verifyVcJws(it, verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.SuccessJwt>()
                    }
            }
        }

        "Invalid jws-expiration in credential is not valid" {
            DummyCredentialDataProvider.getCredential(
                verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT
            ).getOrThrow().let {
                issueCredential(it, expirationDate = Clock.System.now() + 1.hours)
                    .let { wrapVcInJws(it, expirationDate = Clock.System.now() - 1.hours) }
                    .let { signJws(it) }
                    .let {
                        validator.verifyVcJws(it, verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Expiration not matching in credential is not valid" {
            DummyCredentialDataProvider.getCredential(
                verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT
            ).getOrThrow().let {
                it.let { issueCredential(it, expirationDate = Clock.System.now() + 1.hours) }
                    .let { wrapVcInJws(it, expirationDate = Clock.System.now() + 2.hours) }
                    .let { signJws(it) }
                    .let {
                        validator.verifyVcJws(it, verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Invalid NotBefore in credential is not valid" {
            DummyCredentialDataProvider.getCredential(
                verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT
            ).getOrThrow().let {
                it.let { issueCredential(it) }
                    .let { wrapVcInJws(it, issuanceDate = Clock.System.now() + 2.hours) }
                    .let { signJws(it) }
                    .let {
                        validator.verifyVcJws(it, verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }

        "Invalid issuance date in credential is not valid" {
            DummyCredentialDataProvider.getCredential(
                verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT
            ).getOrThrow().let {
                issueCredential(it, issuanceDate = Clock.System.now() + 1.hours)
                    .let { wrapVcInJws(it) }
                    .let { signJws(it) }
                    .let {
                        val validationResult = validator.verifyVcJws(it, verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.SuccessJwt>()

                        validator.checkTimeliness(validationResult.jws).isSuccess shouldBe false
                    }
            }
        }

        "Issuance date and not before not matching is not valid" {
            DummyCredentialDataProvider.getCredential(
                verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT
            ).getOrThrow().let {
                issueCredential(it, issuanceDate = Clock.System.now() - 1.hours)
                    .let { wrapVcInJws(it, issuanceDate = Clock.System.now()) }
                    .let { signJws(it) }
                    .let {
                        validator.verifyVcJws(it, verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.InvalidStructure>()
                    }
            }
        }
    }

    private suspend fun issueCredential(
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
            subjectPublicKey = issuerKeyMaterial.publicKey,
            issuanceDate = issuanceDate,
            expirationDate = exp,
            timePeriod = FixedTimePeriodProvider.timePeriod
        )!!
        val credentialStatus = Status(
            statusList = StatusListInfo(
                index = statusListIndex.toULong(),
                uri = UniformResourceIdentifier(revocationListUrl),
            )
        )

        return VerifiableCredential(
            id = vcId,
            issuer = issuer.keyMaterial.identifier,
            credentialStatus = credentialStatus,
            credentialSubject = sub,
            credentialType = type,
            issuanceDate = issuanceDate,
            expirationDate = expirationDate,
        )
    }

    private fun wrapVcInJws(
        it: VerifiableCredential,
        subject: String = verifierKeyMaterial.identifier,
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

    private suspend fun signJws(vcJws: VerifiableCredentialJws): String = issuerSignVc(
        JwsContentTypeConstants.JWT,
        vcJws,
        VerifiableCredentialJws.serializer()
    ).getOrThrow().serialize()

    private suspend fun wrapVcInJwsWrongKey(vcJws: VerifiableCredentialJws): String {
        val jwsHeader = JwsHeader(
            algorithm = JwsAlgorithm.Signature.ES256,
            keyId = verifierKeyMaterial.identifier,
            type = JwsContentTypeConstants.JWT
        )
        val signatureInput = jwsHeader.serialize().encodeToByteArray().encodeToString(Base64UrlStrict) +
                "." + vcJws.serialize().encodeToByteArray().encodeToString(Base64UrlStrict)
        val signatureInputBytes = signatureInput.encodeToByteArray()
        val signature = issuerKeyMaterial.sign(signatureInputBytes).signature
        return JwsSigned(jwsHeader, vcJws, signature, signatureInputBytes).serialize()
    }

}

package at.asitplus.wallet.lib.agent

import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.Status
import at.asitplus.wallet.lib.data.VerifiableCredential
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.randomCwtOrJwtResolver
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.comparables.shouldBeLessThan
import io.kotest.matchers.comparables.shouldNotBeGreaterThan
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant


val ValidatorVcTest by testSuite {

    withFixtureGenerator {
        object {
            val revocationListUrl: String = "https://wallet.a-sit.at/backend/credentials/status/1"
            val issuerCredentialStore = InMemoryIssuerCredentialStore()
            val issuerKeyMaterial = EphemeralKeyWithoutCert()
            val issuerIdentifier = "https://issuer.example.com/"
            val issuer = IssuerAgent(
                keyMaterial = issuerKeyMaterial,
                issuerCredentialStore = issuerCredentialStore,
                identifier = issuerIdentifier.toUri(),
                randomSource = RandomSource.Default
            )
            val statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
            val validator = ValidatorVcJws(
                validator = Validator(
                    tokenStatusResolver = randomCwtOrJwtResolver(statusListIssuer)
                )
            )
            val issuerSignVc = SignJwt<VerifiableCredentialJws>(issuerKeyMaterial, JwsHeaderCertOrJwk())
            val verifierKeyMaterial = EphemeralKeyWithoutCert()

            suspend fun issueCredential(
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
                val statusListIndex = issuerCredentialStore.createStatusListIndex(
                    CredentialToBeIssued.VcJwt(
                        subject = sub,
                        expiration = exp,
                        scheme = ConstantIndex.AtomicAttribute2023,
                        subjectPublicKey = issuerKeyMaterial.publicKey,
                        userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
                    ),
                    FixedTimePeriodProvider.timePeriod
                ).getOrThrow().statusListIndex
                val credentialStatus = Status(
                    statusList = StatusListInfo(
                        index = statusListIndex,
                        uri = UniformResourceIdentifier(revocationListUrl),
                    )
                )

                return VerifiableCredential(
                    id = vcId,
                    issuer = issuerIdentifier,
                    credentialStatus = credentialStatus,
                    credentialSubject = sub,
                    credentialType = type,
                    issuanceDate = issuanceDate,
                    expirationDate = expirationDate,
                )
            }

            fun wrapVcInJws(
                it: VerifiableCredential,
                subject: String = it.credentialSubject.id,
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

            suspend fun signJws(vcJws: VerifiableCredentialJws): String =
                issuerSignVc(
                    JwsContentTypeConstants.JWT,
                    vcJws,
                    VerifiableCredentialJws.serializer()
                ).getOrThrow().serialize()

            suspend fun wrapVcInJwsWrongKey(vcJws: VerifiableCredentialJws) =
                SignJwt<VerifiableCredentialJws>(
                    issuerKeyMaterial
                ) { header: JwsHeader, keyMaterial: KeyMaterial ->
                    // this should be issuerKeyMaterial.jsonWebKey, but is a wrong key
                    header.copy(jsonWebKey = EphemeralKeyWithoutCert().jsonWebKey)
                }(
                    JwsContentTypeConstants.JWT,
                    vcJws,
                    VerifiableCredentialJws.serializer()
                ).getOrThrow().serialize()

        }
    } - {
        test("credentials are valid for") {
            val credential = it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.verifierKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
                .shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>().apply {
                    // Assert the issuanceOffset in IssuerAgent
                    vc.issuanceDate shouldBeLessThan Clock.System.now().minus(1.minutes)
                    vc.issuanceDate shouldNotBeGreaterThan Clock.System.now()
                }


            it.validator.verifyVcJws(credential.signedVcJws, it.verifierKeyMaterial.publicKey)
                .shouldBeInstanceOf<VerifyCredentialResult.SuccessJwt>()
        }

        test("revoked credentials are not valid") {
            val credential = it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.verifierKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
                .shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

            val value = it.validator.verifyVcJws(credential.signedVcJws, it.verifierKeyMaterial.publicKey)
                .shouldBeInstanceOf<VerifyCredentialResult.SuccessJwt>()
            it.issuerCredentialStore.setStatus(
                timePeriod = FixedTimePeriodProvider.timePeriod,
                index = value.jws.vc.credentialStatus.shouldNotBeNull().statusList.shouldNotBeNull().index,
                status = TokenStatus.Invalid,
            ) shouldBe true

            it.validator.verifyVcJws(credential.signedVcJws, it.verifierKeyMaterial.publicKey)
                .shouldBeInstanceOf<VerifyCredentialResult.SuccessJwt>()

            it.validator.checkRevocationStatus(value.jws)
                .shouldBeInstanceOf<TokenStatusValidationResult.Invalid>()
                .tokenStatus shouldBe TokenStatus.Invalid
        }

        test("wrong subject keyId is not be valid") {
            val credential = it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    EphemeralKeyWithoutCert().publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
                .shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

            it.validator.verifyVcJws(credential.signedVcJws, it.verifierKeyMaterial.publicKey)
                .shouldBeInstanceOf<VerifyCredentialResult.ValidationError>()
        }

        test("credential with invalid JWS format is not valid") {
            val credential = it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.verifierKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
                .shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

            it.validator.verifyVcJws(
                credential.signedVcJws.serialize().replaceFirstChar { "f" },
                it.verifierKeyMaterial.publicKey
            ).shouldBeInstanceOf<VerifyCredentialResult.ValidationError>()
        }

        "Manually created and valid credential is valid" { context ->
            DummyCredentialDataProvider.getCredential(
                context.verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                PLAIN_JWT
            ).getOrThrow().let {
                context.issueCredential(it)
                    .let { context.wrapVcInJws(it) }
                    .let { context.signJws(it) }
                    .let {
                        context.validator.verifyVcJws(it, context.verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.SuccessJwt>()
                    }
            }
        }

        "Wrong key ends in wrong signature is not valid" { context ->
            DummyCredentialDataProvider.getCredential(
                context.verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                PLAIN_JWT
            ).getOrThrow().let {
                context.issueCredential(it)
                    .let { context.wrapVcInJws(it) }
                    .let { context.wrapVcInJwsWrongKey(it) }
                    .let {
                        context.validator.verifyVcJws(it, context.verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.ValidationError>()
                    }
            }
        }

        "Invalid sub in credential is not valid" { context ->
            DummyCredentialDataProvider.getCredential(
                context.verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                PLAIN_JWT
            ).getOrThrow().let {
                context.issueCredential(it)
                    .let { context.wrapVcInJws(it, subject = "vc.id") }
                    .let { context.signJws(it) }
                    .let {
                        context.validator.verifyVcJws(it, context.verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.ValidationError>()
                    }
            }
        }

        "Invalid issuer in credential is not valid" { context ->
            DummyCredentialDataProvider.getCredential(
                context.verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                PLAIN_JWT
            ).getOrThrow().let {
                context.issueCredential(it)
                    .let { context.wrapVcInJws(it, issuer = "vc.issuer") }
                    .let { context.signJws(it) }.let {
                        context.validator.verifyVcJws(it, context.verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.ValidationError>()
                    }
            }
        }

        "Invalid jwtId in credential is not valid" { context ->
            DummyCredentialDataProvider.getCredential(
                context.verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                PLAIN_JWT
            ).getOrThrow().let {
                context.issueCredential(it)
                    .let { context.wrapVcInJws(it, jwtId = "vc.jwtId") }
                    .let { context.signJws(it) }
                    .let {
                        context.validator.verifyVcJws(it, context.verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.ValidationError>()
                    }
            }
        }

        "Invalid expiration in credential is not valid" { context ->
            DummyCredentialDataProvider.getCredential(
                context.verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                PLAIN_JWT
            ).getOrThrow().let {
                context.issueCredential(it, expirationDate = Clock.System.now() - 1.hours)
                    .let {
                        VerifiableCredentialJws(
                            vc = it,
                            subject = it.credentialSubject.id,
                            notBefore = it.issuanceDate,
                            issuer = it.issuer,
                            expiration = Clock.System.now() + 1.hours,
                            jwtId = it.id
                        )
                    }
                    .let { context.signJws(it) }
                    .let {
                        context.validator.verifyVcJws(it, context.verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.ValidationError>()
                    }
            }
        }

        "No expiration date is valid" { context ->
            DummyCredentialDataProvider.getCredential(
                context.verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                PLAIN_JWT
            ).getOrThrow().let {
                context.issueCredential(it, expirationDate = null)
                    .let { context.wrapVcInJws(it) }
                    .let { context.signJws(it) }
                    .let {
                        context.validator.verifyVcJws(it, context.verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.SuccessJwt>()
                    }
            }
        }

        "Invalid jws-expiration in credential is not valid" { context ->
            DummyCredentialDataProvider.getCredential(
                context.verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                PLAIN_JWT
            ).getOrThrow().let {
                context.issueCredential(it, expirationDate = Clock.System.now() + 1.hours)
                    .let { context.wrapVcInJws(it, expirationDate = Clock.System.now() - 1.hours) }
                    .let { context.signJws(it) }
                    .let {
                        context.validator.verifyVcJws(it, context.verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.ValidationError>()
                    }
            }
        }

        "Expiration not matching in credential is not valid" { context ->
            DummyCredentialDataProvider.getCredential(
                context.verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                PLAIN_JWT
            ).getOrThrow().let {
                it.let { context.issueCredential(it, expirationDate = Clock.System.now() + 1.hours) }
                    .let { context.wrapVcInJws(it, expirationDate = Clock.System.now() + 2.hours) }
                    .let { context.signJws(it) }
                    .let {
                        context.validator.verifyVcJws(it, context.verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.ValidationError>()
                    }
            }
        }

        "Invalid NotBefore in credential is not valid" { context ->
            DummyCredentialDataProvider.getCredential(
                context.verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                PLAIN_JWT
            ).getOrThrow().let {
                it.let { context.issueCredential(it) }
                    .let { context.wrapVcInJws(it, issuanceDate = Clock.System.now() + 2.hours) }
                    .let { context.signJws(it) }
                    .let {
                        context.validator.verifyVcJws(it, context.verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.ValidationError>()
                    }
            }
        }

        "Invalid issuance date in credential is not valid" { context ->
            DummyCredentialDataProvider.getCredential(
                context.verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                PLAIN_JWT
            ).getOrThrow().let {
                context.issueCredential(it, issuanceDate = Clock.System.now() + 1.hours)
                    .let { context.wrapVcInJws(it) }
                    .let { context.signJws(it) }
                    .let {
                        context.validator.verifyVcJws(it, context.verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.SuccessJwt>().apply {
                                context.validator.checkCredentialTimeliness(this.jws).isTimely shouldBe false
                            }
                    }
            }
        }

        "Issuance date and not before not matching is not valid" { context ->
            DummyCredentialDataProvider.getCredential(
                context.verifierKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                PLAIN_JWT
            ).getOrThrow().let {
                context.issueCredential(it, issuanceDate = Clock.System.now() - 1.hours)
                    .let { context.wrapVcInJws(it, issuanceDate = Clock.System.now()) }
                    .let { context.signJws(it) }
                    .let {
                        context.validator.verifyVcJws(it, context.verifierKeyMaterial.publicKey)
                            .shouldBeInstanceOf<VerifyCredentialResult.ValidationError>()
                    }
            }
        }
    }
}

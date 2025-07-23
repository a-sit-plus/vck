package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.wallet.lib.agent.SdJwtCreator.toSdJsonObject
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.SdJwtConstants
import at.asitplus.wallet.lib.data.SdJwtTypeMetadata
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderModifierFun
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.time.Clock
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject


class ValidatorSdJwtTest : FreeSpec() {

    private lateinit var issuer: Issuer
    private lateinit var holderKeyMaterial: KeyMaterial
    private lateinit var validator: ValidatorSdJwt

    init {
        beforeEach {
            validator = ValidatorSdJwt()
            issuer = IssuerAgent()
            holderKeyMaterial = EphemeralKeyWithoutCert()
        }

        "credentials are valid for holder's key" {
            val credential = issuer.issueCredential(buildCredentialData()).getOrThrow()
                .shouldBeInstanceOf<Issuer.IssuedCredential.VcSdJwt>()

            validator.verifySdJwt(credential.signedSdJwtVc, holderKeyMaterial.publicKey)
                .shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessSdJwt>()
        }

        "credentials are not valid for some other key" {
            val credential = issuer.issueCredential(buildCredentialData()).getOrThrow()
                .shouldBeInstanceOf<Issuer.IssuedCredential.VcSdJwt>()

            validator.verifySdJwt(credential.signedSdJwtVc, EphemeralKeyWithoutCert().publicKey)
                .shouldBeInstanceOf<Verifier.VerifyCredentialResult.ValidationError>()
        }

        "credentials without cnf are not valid" {
            val credential = issueVcSd(
                buildCredentialData(),
                holderKeyMaterial,
                buildCnf = false,
            ).shouldBeInstanceOf<Issuer.IssuedCredential.VcSdJwt>()

            validator.verifySdJwt(credential.signedSdJwtVc, holderKeyMaterial.publicKey)
                .shouldBeInstanceOf<Verifier.VerifyCredentialResult.ValidationError>()
        }

        "credentials with random subject are valid" {
            val credential = issueVcSd(
                buildCredentialData(),
                holderKeyMaterial,
                scrambleSubject = true,
            ).shouldBeInstanceOf<Issuer.IssuedCredential.VcSdJwt>()

            validator.verifySdJwt(credential.signedSdJwtVc, holderKeyMaterial.publicKey)
                .shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessSdJwt>()
        }

        "credentials are valid with vctm added" {
            val typeMetadata = SdJwtTypeMetadata(
                verifiableCredentialType = "https://www.w3.org/2018/credentials/v1"
            )
            val vctm = typeMetadata.let {
                joseCompliantSerializer.encodeToString(it).encodeToByteArray().encodeToString(Base64UrlStrict)
            }
            val credentialDataWithVctm = buildCredentialData().let {
                it.copy(modifyHeader = JwsHeaderModifierFun {
                    it.copy(vcTypeMetadata = setOf(vctm))
                })
            }
            val credential = issuer.issueCredential(credentialDataWithVctm).getOrThrow()
                .shouldBeInstanceOf<Issuer.IssuedCredential.VcSdJwt>().also {
                    it.signedSdJwtVc.jws.header.vcTypeMetadata.shouldNotBeNull().shouldBeSingleton().first().let {
                        it.decodeToByteArray(Base64UrlStrict).decodeToString().let {
                            joseCompliantSerializer.decodeFromString<SdJwtTypeMetadata>(it)
                        }
                    } shouldBe typeMetadata
                }

            validator.verifySdJwt(credential.signedSdJwtVc, holderKeyMaterial.publicKey)
                .shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessSdJwt>().apply {
                    sdJwtSigned.jws.header.vcTypeMetadata.shouldNotBeNull().shouldBeSingleton().first().let {
                        it.decodeToByteArray(Base64UrlStrict).decodeToString().let {
                            joseCompliantSerializer.decodeFromString<SdJwtTypeMetadata>(it)
                        }
                    } shouldBe typeMetadata
                }
        }

    }

    private fun buildCredentialData(): CredentialToBeIssued.VcSd = DummyCredentialDataProvider.getCredential(
        holderKeyMaterial.publicKey,
        ConstantIndex.AtomicAttribute2023,
        SD_JWT,
    ).getOrThrow().shouldBeInstanceOf<CredentialToBeIssued.VcSd>()
}


private suspend fun issueVcSd(
    credential: CredentialToBeIssued.VcSd,
    holderKeyMaterial: KeyMaterial,
    buildCnf: Boolean = true,
    scrambleSubject: Boolean = false,
): Issuer.IssuedCredential {
    val issuanceDate = Clock.System.now()
    val signIssuedSdJwt: SignJwtFun<JsonObject> = SignJwt(holderKeyMaterial, JwsHeaderCertOrJwk())
    val vcId = "urn:uuid:${uuid4()}"
    val expirationDate = credential.expiration
    val subjectId = credential.subjectPublicKey.didEncoded
    val (sdJwt, disclosures) = credential.claims.toSdJsonObject()
    val vcSdJwt = VerifiableCredentialSdJwt(
        subject = if (scrambleSubject) subjectId.reversed() else subjectId,
        notBefore = issuanceDate,
        issuer = holderKeyMaterial.identifier,
        expiration = expirationDate,
        issuedAt = issuanceDate,
        jwtId = vcId,
        verifiableCredentialType = credential.scheme.sdJwtType ?: credential.scheme.schemaUri,
        selectiveDisclosureAlgorithm = SdJwtConstants.SHA_256,
        confirmationClaim = if (!buildCnf) null else
            ConfirmationClaim(jsonWebKey = credential.subjectPublicKey.toJsonWebKey())
    )
    val vcSdJwtObject = vckJsonSerializer.encodeToJsonElement(vcSdJwt).jsonObject
    val entireObject = buildJsonObject {
        sdJwt.forEach {
            put(it.key, it.value)
        }
        vcSdJwtObject.forEach {
            put(it.key, it.value)
        }
    }
    // inclusion of x5c/jwk may change when all clients can look up the issuer-signed key web-based,
    // i.e. this issuer provides `.well-known/jwt-vc-issuer` file
    val jws = signIssuedSdJwt(
        JwsContentTypeConstants.SD_JWT,
        entireObject,
        JsonObject.serializer(),
    ).getOrElse {
        Napier.w("Could not wrap credential in SD-JWT", it)
        throw RuntimeException("Signing failed", it)
    }
    val sdJwtSigned = SdJwtSigned.issued(jws, disclosures.toList())
    val vcInSdJwt = (listOf(jws.serialize()) + disclosures).joinToString("~", postfix = "~")
    vcInSdJwt shouldBe sdJwtSigned.serialize()
    return Issuer.IssuedCredential.VcSdJwt(
        sdJwtVc = vcSdJwt,
        signedSdJwtVc = sdJwtSigned,
        vcSdJwt = sdJwtSigned.serialize(),
        scheme = credential.scheme,
        subjectPublicKey = credential.subjectPublicKey,
        userInfo = credential.userInfo,
    )
}

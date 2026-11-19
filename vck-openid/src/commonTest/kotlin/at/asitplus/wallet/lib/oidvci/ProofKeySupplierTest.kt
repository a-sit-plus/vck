package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.CredentialRequestProofSupported
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.KeyAttestationRequired
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.ProofTypes
import at.asitplus.openid.SupportedCredentialFormatSdJwt
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotContainAnyOf
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days

/**
 * The key of a credential request comes from a key supplier for every request, so that each key is proven or attested
 * once, and the request records it as the key the credential has to be bound to.
 */
val ProofKeySupplierTest by matrixSuite {

    val issuer = "https://issuer.example.com"
    val withoutAttestation = SupportedCredentialFormatSdJwt(
        sdJwtVcType = "urn:example:credential",
        supportedProofTypes = mapOf(ProofTypes.JWT to CredentialRequestProofSupported()),
    )
    val jwtWithAttestation = SupportedCredentialFormatSdJwt(
        sdJwtVcType = "urn:example:credential",
        supportedProofTypes = mapOf(
            ProofTypes.JWT to CredentialRequestProofSupported(keyAttestationRequired = KeyAttestationRequired())
        ),
    )
    val attestationProof = SupportedCredentialFormatSdJwt(
        sdJwtVcType = "urn:example:credential",
        supportedProofTypes = mapOf(
            ProofTypes.ATTESTATION to CredentialRequestProofSupported(keyAttestationRequired = KeyAttestationRequired())
        ),
    )

    /** Creates a new key on every call and records it, with the request it was asked for. */
    class NewKeys : ProofKeySupplier {
        val supplied = mutableListOf<KeyMaterial>()
        val requests = mutableListOf<ProofKeyRequest>()
        override suspend fun key(request: ProofKeyRequest) = KmmResult.success<KeyMaterial>(EphemeralKeyWithoutCert())
            .also { supplied += it.getOrThrow(); requests += request }
    }

    /** A key attestation of [keys], in this order. */
    suspend fun keyAttestation(keys: List<KeyMaterial>) = SignJwt<KeyAttestationJwt>(
        EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk()
    )(
        type = OpenIdConstants.KEY_ATTESTATION_JWT_TYPE,
        payload = KeyAttestationJwt(
            issuedAt = Clock.System.now(),
            expiration = Clock.System.now() + 1.days,
            attestedKeys = keys.mapTo(linkedSetOf()) { it.jsonWebKey },
        ),
        serializer = KeyAttestationJwt.serializer(),
    ).getOrThrow()

    test("without key attestation, a JWT proof of the supplied key") {
        val supplier = NewKeys()

        val created = JwtProofCreator(keySupplier = supplier)
            .createProof(issuer, withoutAttestation, "client", "nonce").getOrThrow().shouldNotBeNull()

        val key = supplier.supplied.single()
        created.key shouldBe key.publicKey
        JwsCompactTyped<JsonWebToken>(created.proofs.jwt.shouldNotBeNull().single().toString())
            .jws.jwsHeader.jsonWebKey shouldBe key.jsonWebKey
    }

    test("with key attestation, a JWT proof signed with the supplied key, attesting it") {
        val supplier = NewKeys()
        var input: OpenId4VciClient.KeyAttestationInput? = null

        val created = JwtProofCreator(
            keySupplier = supplier,
            loadKeyAttestation = { input = it; catching { keyAttestation(supplier.supplied) } },
        ).createProof(issuer, jwtWithAttestation, "client", "nonce").getOrThrow().shouldNotBeNull()

        val key = supplier.supplied.single()
        input.shouldNotBeNull().keys shouldContainExactly listOf(key.publicKey)
        created.key shouldBe key.publicKey
        JwsCompactTyped<JsonWebToken>(created.proofs.jwt.shouldNotBeNull().single().toString())
            .jws.jwsHeader.jsonWebKey shouldBe key.jsonWebKey
    }

    test("a key attestation without the supplied key first fails") {
        val supplier = NewKeys()

        JwtProofCreator(
            keySupplier = supplier,
            loadKeyAttestation = { catching { keyAttestation(listOf(EphemeralKeyWithoutCert())) } },
        ).createProof(issuer, jwtWithAttestation, "client", "nonce").isFailure shouldBe true

        JwtProofCreator(
            keySupplier = supplier,
            loadKeyAttestation = {
                catching { keyAttestation(listOf(EphemeralKeyWithoutCert(), supplier.supplied.last())) }
            },
        ).createProof(issuer, jwtWithAttestation, "client", "nonce").isFailure shouldBe true
    }

    test("an attestation proof attests the supplied key") {
        val supplier = NewKeys()
        var input: OpenId4VciClient.KeyAttestationInput? = null

        val created = AttestationProofCreator(
            loadKeyAttestation = { input = it; catching { keyAttestation(supplier.supplied) } },
            keySupplier = supplier,
        ).createProof(issuer, attestationProof, "client", "nonce").getOrThrow().shouldNotBeNull()

        val key = supplier.supplied.single().publicKey
        input.shouldNotBeNull().keys shouldContainExactly listOf(key)
        created.key shouldBe key
        created.proofs.attestation.shouldNotBeNull().shouldHaveSize(1)
    }

    test("the key supplier gets the proof type and the key attestation requirements of the request") {
        val required = KeyAttestationRequired(keyStorage = listOf("iso_18045_high"))
        val jwtRequiring = SupportedCredentialFormatSdJwt(
            sdJwtVcType = "urn:example:credential",
            supportedProofTypes = mapOf(
                ProofTypes.JWT to CredentialRequestProofSupported(keyAttestationRequired = required)
            ),
        )
        val attestationRequiring = SupportedCredentialFormatSdJwt(
            sdJwtVcType = "urn:example:credential",
            supportedProofTypes = mapOf(
                ProofTypes.ATTESTATION to CredentialRequestProofSupported(keyAttestationRequired = required)
            ),
        )
        val supplier = NewKeys()

        JwtProofCreator(keySupplier = supplier)
            .createProof(issuer, withoutAttestation, "client", "nonce").getOrThrow().shouldNotBeNull()
        JwtProofCreator(
            keySupplier = supplier,
            loadKeyAttestation = { catching { keyAttestation(supplier.supplied.takeLast(1)) } },
        ).createProof(issuer, jwtRequiring, "client", "nonce").getOrThrow().shouldNotBeNull()
        AttestationProofCreator(
            loadKeyAttestation = { catching { keyAttestation(supplier.supplied.takeLast(1)) } },
            keySupplier = supplier,
        ).createProof(issuer, attestationRequiring, "client", "nonce").getOrThrow().shouldNotBeNull()

        supplier.requests shouldContainExactly listOf(
            ProofKeyRequest(ProofTypes.JWT, keyAttestationRequired = null),
            ProofKeyRequest(ProofTypes.JWT, required),
            ProofKeyRequest(ProofTypes.ATTESTATION, required),
        )
    }

    test("an attestation proof of another key than the supplied one fails") {
        val supplier = NewKeys()

        AttestationProofCreator(
            loadKeyAttestation = { catching { keyAttestation(listOf(EphemeralKeyWithoutCert())) } },
            keySupplier = supplier,
        ).createProof(issuer, attestationProof, "client", "nonce").isFailure shouldBe true
    }

    test("an attestation proof without key supplier reports no key, as before") {
        AttestationProofCreator { catching { keyAttestation(listOf(EphemeralKeyWithoutCert())) } }
            .createProof(issuer, attestationProof, "client", "nonce").getOrThrow().shouldNotBeNull()
            .key shouldBe null
    }

    test("a single key is proven in every request") {
        val key = EphemeralKeyWithoutCert()
        val creator = JwtProofCreator(key)

        creator.createProof(issuer, withoutAttestation, "client", "nonce").getOrThrow().shouldNotBeNull()
            .key shouldBe key.publicKey
        creator.createProof(issuer, withoutAttestation, "client", "new nonce").getOrThrow().shouldNotBeNull()
            .key shouldBe key.publicKey
    }

    test("every credential request gets a fresh key, and records it") {
        val supplier = NewKeys()
        val client = OpenId4VciClient(proofCreators = listOf(JwtProofCreator(keySupplier = supplier)))
        val metadata = IssuerMetadata(
            credentialIssuer = issuer,
            credentialEndpointUrl = "$issuer/credential",
            supportedCredentialConfigurations = mapOf("configuration" to withoutAttestation),
        )

        val first = client.createCredential(metadata, "configuration", "nonce").getOrThrow()
        val retry = client.createCredential(metadata, "configuration", "new nonce").getOrThrow()

        first.shouldBeInstanceOf<OpenId4VciClient.CredentialRequest.Plain>()
        first.proofKeys shouldContainExactly setOf(supplier.supplied[0].publicKey)
        retry.proofKeys shouldContainExactly setOf(supplier.supplied[1].publicKey)
        retry.proofKeys shouldNotContainAnyOf first.proofKeys
    }
}

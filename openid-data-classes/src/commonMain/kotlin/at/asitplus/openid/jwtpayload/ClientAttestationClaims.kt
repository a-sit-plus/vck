package at.asitplus.openid.jwtpayload

import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JwtClaimNames
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered.ClaimNames
import at.asitplus.signum.indispensable.josef.JwtPayload
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlin.time.Instant

/**
 * Defined in [draft-ietf-oauth-attestation-based-client-auth](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-10)
 * Can be [Attestation] or [ProofOfPossession]
 */
@Serializable(with = ClientAttestationClaims.Serializer::class)
sealed interface ClientAttestationClaims: JwtPayload {

    @Serializable(with = Attestation.Serializer::class)
    interface Attestation : ClientAttestationClaims {
        override val subject: String
        override val expiration: Instant

        /**
         * OID4VP: This claim contains the confirmation method as defined in RFC7800. It MUST contain a JWK as defined in
         * Section 3.2 of RFC7800. This claim determines the public key for which the corresponding private key the
         * Verifier MUST proof possession of when presenting the Verifier Attestation JWT. This additional security measure
         * allows the Verifier to obtain a Verifier Attestation JWT from a trusted issuer and use it for a long time
         * independent of that issuer without the risk of an adversary impersonating the Verifier by replaying a captured
         * attestation.
         */
        @SerialName(ClaimNames.RFC7800.CNF)
        val confirmationClaim: ConfirmationClaim

        object Serializer : JsonContentPolymorphicSerializer<Attestation>(Attestation::class) {
            override fun selectDeserializer(element: JsonElement): DeserializationStrategy<Attestation> =
                when {
                    JwtClaimNames.UnregisteredClaims.EudiTs3Claims.WALLET_NAME in element.jsonObject -> WalletAttestationPayload.serializer()
                    else -> ClientAttestationPayload.serializer()
                }
        }

    }

    @Serializable(with = ProofOfPossession.Serializer::class)
    interface ProofOfPossession : ClientAttestationClaims {
        override val audience: String
        override val jwtId: String
        override val issuedAt: Instant

        /**
         * OPTIONAL for Pop and MUST be absent for normal
         *
         * challenge: OPTIONAL.  The challenge (challenge) claim MUST specify
         *       a String value that is provided by the Authorization Server or
         *       Resource Server for the client to include in the Client
         *       Attestation PoP JWT.
         */
        @SerialName(JwtClaimNames.UnregisteredClaims.DraftIetfOauthAttestation.CHALLENGE)
        val challenge: String?

        object Serializer : JsonContentPolymorphicSerializer<ProofOfPossession>(ProofOfPossession::class) {
            override fun selectDeserializer(element: JsonElement): DeserializationStrategy<ProofOfPossession> =
                when {
                    JwtClaimNames.UnregisteredClaims.EudiTs3Claims.WALLET_NAME in element.jsonObject -> WalletAttestationPopPayload.serializer()
                    else -> ClientAttestationPopPayload.serializer()
                }
        }
    }

    object Serializer : JsonContentPolymorphicSerializer<ClientAttestationClaims>(ClientAttestationClaims::class) {
        override fun selectDeserializer(element: JsonElement): DeserializationStrategy<ClientAttestationClaims> = when {
            ClaimNames.RFC7800.CNF in element.jsonObject -> Attestation.serializer()
            else -> ProofOfPossession.serializer()
        }
    }
}

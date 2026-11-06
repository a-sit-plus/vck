package at.asitplus.wallet.lib.etsi

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.etsi.ListOfTrustedEntities
import at.asitplus.etsi.TrustListPayload
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.agent.requireTrustedSigningCertificate
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.jws.VerifyJwsObjectJades
import at.asitplus.wallet.lib.jws.VerifyJwsSignature
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureFun
import at.asitplus.wallet.lib.validation.TimelinessException
import kotlin.jvm.JvmOverloads
import kotlin.time.Clock

/** Verifies a List of Trusted Entities as published by its scheme operator, see [VerifyLoTE]. */
fun interface VerifyLoTEFun {
    /**
     * @param signedLote the list as published, i.e. a JWS in compact serialization
     * @param inForce the list of the same `LoTEType` currently in force, if any, to reject an older list
     * @return the list, if it passed every check
     */
    suspend operator fun invoke(
        signedLote: String,
        inForce: ListOfTrustedEntities?,
    ): KmmResult<ListOfTrustedEntities>
}

/**
 * Verifies a List of Trusted Entities as published by its scheme operator, e.g. the European Commission on a
 * [LoTEStage]: signed with a compact JAdES baseline B signature (ETSI TS 119 602 V1.1.1, D.4, E.4, F.4, G.4, H.4,
 * I.4), by one of the certificates the scheme operator publishes "to be used to verify the signature or seal on the
 * lists" (CIR (EU) 2024/2980, Article 5(4)(c)), i.e. [trustedSigners].
 *
 * A list is returned only if it passes all of these checks, so the lists for [LoTETrustAnchorProvider] should come
 * from here:
 * - The signing certificate in `x5c` is one of [trustedSigners], or issued by one, see
 *   [requireTrustedSigningCertificate], and matches the `x5t#o` header parameter, see [VerifyJwsObjectJades].
 * - The JWS signature verifies with that certificate.
 * - The Organization of the signing certificate is one of the `SchemeOperatorName` values: "The "Country code"
 *   and "Organization" fields in Subject Distinguished Name of the certificate supporting the AdES digital signature
 *   shall match respectively the "Scheme Territory" and one of the "Scheme operator name" values" (ETSI TS 119 602
 *   V1.1.1, 6.8.0). The Country is not compared: the Commission seals its lists with a certificate for a Member State,
 *   e.g. `LU`, but sets their `SchemeTerritory` to `EU`, as 6.1.5 a) 3) and Tables D.1 to I.1 require, so every list
 *   would be rejected.
 * - The list is not expired: "LoTE with a Next update occurring in the past shall be discarded as expired as a
 *   measure to reduce the risk of a substitution by an attacker with an old LoTE" (ETSI TS 119 602 V1.1.1, 6.3.15).
 *   A closed list, whose `NextUpdate` is `null`, does not expire.
 * - Its `LoTESequenceNumber` is not lower than the one of the list `inForce`: it "shall not, under any
 *   circumstance, be re-cycled to "1" or to any value lower than the one of the LoTE currently in force" (ETSI
 *   TS 119 602 V1.1.1, 6.3.2).
 */
class VerifyLoTE @JvmOverloads constructor(
    /** Certificates to verify the signature or seal on the lists, as published by the scheme operator. */
    val trustedSigners: TrustedCertificates,
    val verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(),
    val clock: Clock = Clock.System,
) : VerifyLoTEFun {

    override suspend operator fun invoke(
        signedLote: String,
        inForce: ListOfTrustedEntities?,
    ): KmmResult<ListOfTrustedEntities> = catching {
        val now = clock.now()
        val jws = JwsCompact(signedLote)
        val signingCertificate = jws.jwsHeader.certificateChain
            .requireTrustedSigningCertificate(trustedSigners, now)
        VerifyJwsObjectJades(VerifyJwsObjectFun {
            verifyJwsSignature(it, signingCertificate.decodedPublicKey.getOrThrow())
        }).invoke(jws).getOrThrow()

        val lote = jws.getPayload<TrustListPayload>().getOrThrow().loTe
        val information = requireNotNull(lote.listAndSchemeInformation) { "LoTE has no ListAndSchemeInformation" }
        val organization = signingCertificate.organizationName
        require(information.schemeOperatorName.any { it.value == organization }) {
            "Organization of the signing certificate ($organization) is not a SchemeOperatorName of the LoTE"
        }
        information.nextUpdate?.let { nextUpdate ->
            if (nextUpdate < now) {
                throw TimelinessException("The LoTE is expired", now, information.listIssueDateTime, nextUpdate)
            }
        }
        inForce?.listAndSchemeInformation?.let { current ->
            require(current.loteType == information.loteType) {
                "LoTE in force has type ${current.loteType}, not ${information.loteType}"
            }
            require(information.loTESequenceNumber >= current.loTESequenceNumber) {
                "LoTESequenceNumber ${information.loTESequenceNumber} is lower than the one in force " +
                        "(${current.loTESequenceNumber})"
            }
        }
        lote
    }
}

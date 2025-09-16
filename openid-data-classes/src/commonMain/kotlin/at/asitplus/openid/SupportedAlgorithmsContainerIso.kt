package at.asitplus.openid

import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

@Serializable
data class SupportedAlgorithmsContainerIso(
    /**
     * OID4VP: OPTIONAL. A non-empty array containing cryptographic algorithm identifiers. The Credential MUST be
     * considered to fulfill the requirement(s) expressed in this parameter if one of the following is true:
     * 1) The value in the array matches the `alg` value in the IssuerAuth COSE header.
     * 2) The value in the array is a fully specified algorithm according to
     * [I-D.ietf-jose-fully-specified-algorithms](https://datatracker.ietf.org/doc/html/draft-ietf-jose-fully-specified-algorithms-13)
     * and the combination of the `alg` value in the `IssuerAuth` COSE header and the curve used by the signing key of
     * the COSE structure matches the combination of the algorithm and curve identified by the fully specified
     * algorithm. As an example, if the `IssuerAuth` structure contains an `alg` header with value `-7` (which stands
     * for ECDSA with SHA-256 in [IANA.COSE](https://www.iana.org/assignments/cose/cose.xhtml) and is signed by a
     * P-256 key, then it matches an [issuerAuthAlgorithmInts] element of `-7` and `-9`.
     */
    @SerialName("issuerauth_alg_values")
    val issuerAuthAlgorithmInts: Set<Int>? = null,

    /**
     * OID4VP: OPTIONAL. A non-empty array containing cryptographic algorithm identifiers. The Credential MUST be
     * considered to fulfill the requirement(s) expressed in this parameter if one of the following is true:
     * 1) The value in the array matches the `alg` value in the `DeviceSignature` or `DeviceMac` COSE header.
     * 2) The value in the array is a fully-specified algorithm according to
     * [I-D.ietf-jose-fully-specified-algorithms](https://datatracker.ietf.org/doc/html/draft-ietf-jose-fully-specified-algorithms-13)
     * and the combination of the `alg` value in the DeviceSignature COSE header and the curve used by the signing key
     * of the COSE structure matches the combination of the algorithm and curve identified by the fully-specified
     * algorithm.
     * 3) The `alg` of the `DeviceMac` COSE header is `HMAC 256/256` (as described in Section 9.1.3.5 of [ISO.18013-5])
     * and the curve of the device key (from Table 22 of [ISO.18013-5]) matches a value in the array using the
     * identifiers defined in
     * [table 2](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#name-mapping-of-curves-to-alg-id)
     * .
     */
    @SerialName("deviceauth_alg_values")
    val deviceAuthAlgorithmInts: Set<Int>? = null,
) {
    /**
     * OID4VP: OPTIONAL. A non-empty array containing cryptographic algorithm identifiers. The Credential MUST be
     * considered to fulfill the requirement(s) expressed in this parameter if one of the following is true:
     * 1) The value in the array matches the `alg` value in the IssuerAuth COSE header.
     * 2) The value in the array is a fully specified algorithm according to
     * [I-D.ietf-jose-fully-specified-algorithms](https://datatracker.ietf.org/doc/html/draft-ietf-jose-fully-specified-algorithms-13)
     * and the combination of the `alg` value in the `IssuerAuth` COSE header and the curve used by the signing key of
     * the COSE structure matches the combination of the algorithm and curve identified by the fully specified
     * algorithm. As an example, if the `IssuerAuth` structure contains an `alg` header with value `-7` (which stands
     * for ECDSA with SHA-256 in [IANA.COSE](https://www.iana.org/assignments/cose/cose.xhtml) and is signed by a
     * P-256 key, then it matches an [issuerAuthAlgorithmInts] element of `-7` and `-9`.
     */
    @Transient
    val issuerAuthAlgorithms: Set<CoseAlgorithm>? =
        issuerAuthAlgorithmInts?.mapNotNull { it.toCoseAlgorithm() }?.toSet()

    /**
     * OID4VP: OPTIONAL. A non-empty array containing cryptographic algorithm identifiers. The Credential MUST be
     * considered to fulfill the requirement(s) expressed in this parameter if one of the following is true:
     * 1) The value in the array matches the `alg` value in the `DeviceSignature` or `DeviceMac` COSE header.
     * 2) The value in the array is a fully-specified algorithm according to
     * [I-D.ietf-jose-fully-specified-algorithms](https://datatracker.ietf.org/doc/html/draft-ietf-jose-fully-specified-algorithms-13)
     * and the combination of the `alg` value in the DeviceSignature COSE header and the curve used by the signing key
     * of the COSE structure matches the combination of the algorithm and curve identified by the fully-specified
     * algorithm.
     * 3) The `alg` of the `DeviceMac` COSE header is `HMAC 256/256` (as described in Section 9.1.3.5 of [ISO.18013-5])
     * and the curve of the device key (from Table 22 of [ISO.18013-5]) matches a value in the array using the
     * identifiers defined in
     * [table 2](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#name-mapping-of-curves-to-alg-id)
     * .
     */
    @Transient
    val deviceAuthAlgorithms: Set<CoseAlgorithm>? = deviceAuthAlgorithmInts
        ?.flatMap { it.coercedCoseAlgorithmValues() }?.toSet()


    /**
     * [OpenID4VP Table 2](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#table-2):
     * Mapping of curves to `alg` identifiers used for the HMAC 256/256 case
     */
    private fun Int.coercedCoseAlgorithmValues(): List<CoseAlgorithm> = when (this) {
        -65537, -65538, -65539 -> listOfNotNull(CoseAlgorithm.MAC.HS256, toCoseAlgorithm())
        else -> listOfNotNull(toCoseAlgorithm())
    }
}
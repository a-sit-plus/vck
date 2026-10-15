package at.asitplus.iso

/**
 * Age attestation handling according to ISO/IEC 18013-5:2021, 7.2.5
 *
 * An mdoc carries age information as a set of booleans named `age_over_NN`. A verifier will routinely request a
 * threshold the credential does not carry, even though the credential can answer the question, because these
 * booleans imply each other
 * This object implements the selection rule the standard prescribes. It only ever selects among the attestations
 * the issuer signed
 */
object AgeAttestation {

    /**
     * An age attestation identifier has the format `age_over_NN` where NN is a value from 00 to 99 (7.2.5).
     * A single digit is accepted as well, so that a reader sending `age_over_8` is understood.
     */
    private val AGE_OVER_REGEX = Regex("""^age_over_(\d{1,2})$""")

    /** The NN of [elementIdentifier], or `null` if it is not an age attestation identifier. */
    fun thresholdOf(elementIdentifier: String): Int? =
        AGE_OVER_REGEX.matchEntire(elementIdentifier)?.groupValues?.get(1)?.toIntOrNull()

    /** Whether [elementIdentifier] is an age attestation identifier, i.e. of the form `age_over_NN`. */
    fun isAgeAttestation(elementIdentifier: String): Boolean = thresholdOf(elementIdentifier) != null

    /**
     * For an age attestation identifier this implements 7.2.5:
     * 1. Among the attestations with value `true`, take the one whose NN is equal to or larger than the requested
     *    NN with the smallest difference.
     * 2. Otherwise, among the attestations with value `false`, take the one whose NN is equal to or smaller than
     *    the requested NN with the smallest difference.
     * 3. Otherwise, no age attestation can answer the request.
     *
     * @return the identifier of the element to disclose, or `null` if the request cannot be answered.
     */
    fun resolve(requestedElement: String, available: Map<String, Any?>): String? {
        val requestedThreshold = thresholdOf(requestedElement)
            ?: return requestedElement.takeIf { available.containsKey(it) }

        val attestations = available.mapNotNull { (identifier, value) ->
            val threshold = thresholdOf(identifier) ?: return@mapNotNull null
            val attested = value as? Boolean ?: return@mapNotNull null
            Attestation(identifier, threshold, attested)
        }

        // nearest "true" at or above the requested threshold.
        attestations
            .filter { it.attested && it.threshold >= requestedThreshold }
            .minByOrNull { it.threshold - requestedThreshold }
            ?.let { return it.identifier }

        // nearest "false" at or below the requested threshold.
        attestations
            .filter { !it.attested && it.threshold <= requestedThreshold }
            .minByOrNull { requestedThreshold - it.threshold }
            ?.let { return it.identifier }

        return null
    }

    private data class Attestation(
        val identifier: String,
        val threshold: Int,
        val attested: Boolean,
    )
}
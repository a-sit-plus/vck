package at.asitplus.wallet.lib.data

/**
 * Intermediate class used by [at.asitplus.wallet.lib.agent.Validator.verifyVpJws] when parsing a verifiable presentation.
 */
data class VerifiablePresentationParsed(
    val id: String,
    val type: String,
    val verifiableCredentials: Array<VerifiableCredentialJws> = arrayOf(),
    val revokedVerifiableCredentials: Array<VerifiableCredentialJws> = arrayOf(),
    val invalidVerifiableCredentials: Array<String> = arrayOf(),
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as VerifiablePresentationParsed

        if (id != other.id) return false
        if (type != other.type) return false
        if (!verifiableCredentials.contentEquals(other.verifiableCredentials)) return false
        if (!revokedVerifiableCredentials.contentEquals(other.revokedVerifiableCredentials)) return false
        if (!invalidVerifiableCredentials.contentEquals(other.invalidVerifiableCredentials)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + type.hashCode()
        result = 31 * result + verifiableCredentials.contentHashCode()
        result = 31 * result + revokedVerifiableCredentials.contentHashCode()
        result = 31 * result + invalidVerifiableCredentials.contentHashCode()
        return result
    }
}
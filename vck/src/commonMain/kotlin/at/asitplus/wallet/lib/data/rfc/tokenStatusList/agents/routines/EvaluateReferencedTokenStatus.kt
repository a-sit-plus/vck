package at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.routines

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus

interface EvaluateReferencedTokenStatus<ReferencedToken: Any> {
    operator fun invoke(
        referencedToken: ReferencedToken,
    ): TokenStatus

    class FromStatusMechanisms<ReferencedToken : Any, StatusMechanism: Any>(
        val validateReferencedTokenAsWebToken: (ReferencedToken) -> Unit,
        val extractStatusMechanisms: (ReferencedToken) -> List<StatusMechanism>,
        val resolveTokenStatus: (StatusMechanism) -> TokenStatus,
    ) {
        operator fun invoke(
            referencedToken: ReferencedToken,
        ): TokenStatus {
            /**
             * Upon receiving a Referenced Token, a Relying Party MUST first perform the validation of the
             * Referenced Token - e.g., checking for expected attributes, valid signature, expiration time.
             * The processing rules for JWT or CWT precede any evaluation of a Referenced Token's status.
             * For example, if a token is evaluated as being expired through the "exp" (Expiration Time)
             * but also has a status of 0x00 ("VALID"), the token is considered expired. As this is out of
             * scope of this document, this validation is not be described here, but is expected to be done
             * according to the format of the Referenced Token.
             */
            validateReferencedTokenAsWebToken(referencedToken)

            /**
             * Check for the existence of a status claim, check for the existence of a status_list
             * claim within the status claim and validate that the content of status_list adheres
             * to the rules defined in Section 6.2 for JWTs and Section 6.3 for CWTs. This step can
             * be overruled if defined within the Referenced Token Format natively
             */
            val statusMechanisms = extractStatusMechanisms(referencedToken)
            if(statusMechanisms.isEmpty()) {
                throw IllegalArgumentException("Argument `referencedToken` does not define any status mechanisms.")
            }
            return statusMechanisms.firstNotNullOfOrNull {
                runCatching {
                    resolveTokenStatus(it)
                }.getOrNull()
            } ?: throw IllegalStateException("Token status could not be resolved.")
        }
    }
}
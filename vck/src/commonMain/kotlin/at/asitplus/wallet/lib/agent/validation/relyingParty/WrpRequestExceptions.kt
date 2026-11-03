package at.asitplus.wallet.lib.agent.validation.relyingParty

/**
 * The request does not contain a registration certificate (WRPRC), e.g. it has no `verifier_info`, or no ISO
 * `DocRequest` carries an `euWrprc`.
 */
class MissingRegistrationCertificateException(message: String) : IllegalArgumentException(message)

/**
 * The request contains a registration certificate (WRPRC) that can not be used, e.g. because it can not be parsed,
 * or because the request contains more than one.
 */
class InvalidRegistrationCertificateException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/**
 * The request can not be validated for a wallet relying party, e.g. because it is not signed.
 */
class UnsupportedWrpRequestException(message: String) : IllegalArgumentException(message)

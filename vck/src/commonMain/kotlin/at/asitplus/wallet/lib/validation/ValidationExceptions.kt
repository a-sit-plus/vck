package at.asitplus.wallet.lib.validation

import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.RequestDataValidity
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrpCredentialRequest
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import kotlin.time.Instant

/** The [status] of an artifact was determined, but is not accepted by the [StatusPolicy]. */
class TokenStatusException(
    val status: TokenStatus
) : IllegalArgumentException("Token status $status is not accepted")

/**
 * A validity period, from [notBefore] to [notAfter] (either may be absent), does not contain [evaluatedAt], taking
 * the leeway of the [ValidationPolicy] into account.
 */
class TimelinessException(
    message: String,
    val evaluatedAt: Instant,
    val notBefore: Instant?,
    val notAfter: Instant?,
) : IllegalArgumentException(message)

/**
 * A wallet-relying party requests credentials or claims its registration certificate does not cover: [requests]
 * holds each such request with what is registered of it, e.g. to tell the user which claims are not registered.
 */
class UnregisteredRequestException(
    val requests: List<Pair<WrpCredentialRequest, RequestDataValidity>>,
) : IllegalArgumentException("${requests.size} credential request(s) are not registered")

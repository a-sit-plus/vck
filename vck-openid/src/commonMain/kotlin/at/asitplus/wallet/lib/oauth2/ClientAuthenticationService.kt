package at.asitplus.wallet.lib.oauth2

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.wallet.lib.etsi.Success

/**
 * Handles authenticating the OAuth 2.0 client for an OAuth 2.0 authorization server,
 * see [SimpleAuthorizationService] and subclasses of this interface.
 */
interface ClientAuthenticationService {
    /** Authenticates the client by some data in the request. */
    suspend fun authenticateClient(
        httpRequest: RequestInfo?,
        clientId: String?,
    ): KmmResult<Success>
}

/** Does not verify the client authentication at all */
object NoopClientAuthenticationService : ClientAuthenticationService {
    override suspend fun authenticateClient(
        httpRequest: RequestInfo?,
        clientId: String?
    ): KmmResult<Success> = catching {
        Success
    }
}

import Foundation

public extension TokenResponseParameters {
    /// Matches Kotlin's defaults, with required arguments first.
    convenience init(
        accessToken: String,
        tokenType: String,
        refreshToken: String? = nil,
        expires: Any? = nil,
        scope: String? = nil,
        authorizationPending: KotlinBoolean? = nil,
        interval: Any? = nil,
        authorizationDetails: Set<AuthorizationDetails>? = nil,
        credentialId: String? = nil
    ) {
        self.init(
            accessToken: accessToken, refreshToken: refreshToken, tokenType: tokenType,
            expires: expires, scope: scope, authorizationPending: authorizationPending,
            interval: interval, authorizationDetails: authorizationDetails, credentialId: credentialId
        )
    }
}

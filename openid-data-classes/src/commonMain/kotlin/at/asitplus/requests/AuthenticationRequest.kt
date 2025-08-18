package at.asitplus.requests

import kotlinx.serialization.Serializable

/**
 * Generic concept Authentication Request
 * It is made up of Request data (CSC, OpenID) and
 * the specification defining transmission (OAuth2, JAR, DC-API)
 */
@Serializable(with = AuthenticationRequestSerializer::class)
sealed interface AuthenticationRequest : RequestParameters
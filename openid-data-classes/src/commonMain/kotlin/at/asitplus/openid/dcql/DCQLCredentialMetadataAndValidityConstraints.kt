package at.asitplus.openid.dcql

import kotlinx.serialization.Serializable

@Serializable(with = DCQLCredentialMetadataAndValidityConstraintsSerializer::class)
sealed interface DCQLCredentialMetadataAndValidityConstraints

/**
 * Passes an empty constraint object as per https://github.com/openid/OpenID4VP/issues/590
 *
 * This should only be used if the defined credential explicitly does not introduce any constraints
 */
@Serializable
object DCQLEmptyCredentialMetadataAndValidityConstraints : DCQLCredentialMetadataAndValidityConstraints



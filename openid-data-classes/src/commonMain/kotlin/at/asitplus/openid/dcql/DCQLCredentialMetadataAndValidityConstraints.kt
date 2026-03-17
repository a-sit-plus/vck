package at.asitplus.openid.dcql

import at.asitplus.KmmResult
import kotlinx.serialization.Serializable

@Serializable(with = DCQLCredentialMetadataAndValidityConstraintsSerializer::class)
sealed interface DCQLCredentialMetadataAndValidityConstraints {
    fun validateCredentialConformance(
        credential: DCQLCredential,
    ): KmmResult<Unit> = when (this) {
        DCQLEmptyCredentialMetadataAndValidityConstraints -> when (credential) {
            is DCQLIsoMdocCredential,
            is DCQLSdJwtCredential,
            is DCQLVcJwsCredential -> KmmResult.failure(IllegalArgumentException("Incompatible credential format `${credential.format}` for metadata constraints $this"))
        }

        is DCQLIsoMdocCredentialMetadataAndValidityConstraints -> when (credential) {
            is DCQLIsoMdocCredential -> validateCredentialConformance(credential)

            is DCQLSdJwtCredential,
            is DCQLVcJwsCredential -> KmmResult.failure(IllegalArgumentException("Incompatible credential format `${credential.format}` for metadata constraints $this"))
        }

        is DCQLJwtVcCredentialMetadataAndValidityConstraints -> when (credential) {
            is DCQLVcJwsCredential -> validateCredentialConformance(credential)

            is DCQLIsoMdocCredential,
            is DCQLSdJwtCredential -> KmmResult.failure(IllegalArgumentException("Incompatible credential format `${credential.format}` for metadata constraints $this"))
        }

        is DCQLSdJwtCredentialMetadataAndValidityConstraints -> when (credential) {
            is DCQLSdJwtCredential -> validateCredentialConformance(credential)

            is DCQLIsoMdocCredential,
            is DCQLVcJwsCredential -> KmmResult.failure(IllegalArgumentException("Incompatible credential format `${credential.format}` for metadata constraints $this"))
        }
    }
}

/**
 * Passes an empty constraint object as per https://github.com/openid/OpenID4VP/issues/590
 *
 * This should only be used if the defined credential explicitly does not introduce any constraints
 */
@Serializable
object DCQLEmptyCredentialMetadataAndValidityConstraints : DCQLCredentialMetadataAndValidityConstraints



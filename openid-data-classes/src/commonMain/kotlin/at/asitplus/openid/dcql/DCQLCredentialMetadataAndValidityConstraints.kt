package at.asitplus.openid.dcql

import kotlinx.serialization.Serializable

@Serializable(with = DCQLCredentialMetadataAndValidityConstraintsSerializer::class)
interface DCQLCredentialMetadataAndValidityConstraints



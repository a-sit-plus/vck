package at.asitplus.openid.dcql

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 * SPDX-License-Identifier: Apache-2.0
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.data.NonEmptyList
import at.asitplus.openid.CredentialFormatEnum
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 *  6.1. Credential Query
 *
 * A Credential Query is an object representing a request for a presentation of one Credential.
 * Note that multiple Credential Queries in a request MAY request a presentation of the same Credential.
 */
@Serializable
data class DCQLJwtVcCredentialQuery(
    @SerialName(DCQLCredentialQuery.SerialNames.ID)
    override val id: DCQLCredentialQueryIdentifier,
    @SerialName(DCQLCredentialQuery.SerialNames.META)
    override val meta: DCQLJwtVcCredentialMetadataAndValidityConstraints,
    @SerialName(DCQLCredentialQuery.SerialNames.CLAIMS)
    override val claims: DCQLClaimsQueryList<DCQLJsonClaimsQuery>? = null,
    @SerialName(DCQLCredentialQuery.SerialNames.CLAIM_SETS)
    override val claimSets: NonEmptyList<List<DCQLClaimsQueryIdentifier>>? = null,
    @SerialName(DCQLCredentialQuery.SerialNames.MULTIPLE)
    override val multiple: Boolean? = false,
    @SerialName(DCQLCredentialQuery.SerialNames.TRUSTED_AUTHORITIES)
    override val trustedAuthorities: NonEmptyList<DCQLTrustedAuthorityQueryEntry>? = null,
    @SerialName(DCQLCredentialQuery.SerialNames.REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING)
    override val requireCryptographicHolderBinding: Boolean? = true,
    @SerialName(DCQLCredentialQuery.SerialNames.FORMAT)
    @EncodeDefault(mode = EncodeDefault.Mode.ALWAYS)
    override val format: CredentialFormatEnum = CREDENTIAL_FORMAT,
) : DCQLCredentialQuery {
    init {
        validate()
    }

    companion object {
        val CREDENTIAL_FORMAT = CredentialFormatEnum.JWT_VC
    }

    override fun validate() {
        super.validate()
        require(format == CREDENTIAL_FORMAT) {
            "Value has an invalid format identifier in this context."
        }
    }
}
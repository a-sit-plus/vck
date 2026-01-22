package at.asitplus.openid.dcql

/*
 * Software Name : vc-k
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 * SPDX-License-Identifier: Apache-2.0
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.KmmResult
import at.asitplus.catching
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


@Serializable
data class DCQLJwtVcCredentialMetadataAndValidityConstraints(
    /**
     * OID4VP 1.0: type_values: REQUIRED. A non-empty array of string arrays.
     * The value of each element in the type_values array is a non-empty array specifying the
     * fully expanded types (IRIs) that the Verifier accepts in a Presentation, after applying
     * the @context to the Verifiable Credential. If a type value in a Verifiable Credential is not
     * defined in any @context, it remains unchanged, i.e., remains a relative IRI after JSON-LD
     * processing. For this reason, JSON-LD processing MAY be skipped in such cases and the
     * relative IRI is considered to be the fully expanded type, as applying the @context would not
     * alter the value. Implementations MAY use alternative mechanisms to obtain the fully expanded
     * types, as long as the results are equivalent to those produced by JSON-LD processing.
     * Each of the top-level arrays specifies one alternative to match the fully expanded type
     * values of the Verifiable Credential against. Each inner array specifies a set of fully
     * expanded types that MUST be present in the fully expanded types in the type property of
     * the Verifiable Credential, regardless of order or the presence of additional types.
     */
    @SerialName(SerialNames.TYPE_VALUES) val typeValues: List<List<String>>
) : DCQLCredentialMetadataAndValidityConstraints {
    object SerialNames {
        const val TYPE_VALUES = "type_values"
    }

    fun validate(actualCredentialTypes: List<String>?): KmmResult<Unit> = catching {
        var valid = false
        if (actualCredentialTypes != null) {
            for (typeValue in typeValues ){
                if ( actualCredentialTypes.containsAll(typeValue) ) {
                    valid = true
                }
            }
        }

        when (valid){
            true -> Unit
            false -> throw IllegalArgumentException("Incompatible JWT-VC document type")
        }

    }
}
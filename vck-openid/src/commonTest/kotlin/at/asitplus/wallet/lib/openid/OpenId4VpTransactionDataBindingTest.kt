package at.asitplus.wallet.lib.openid

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString

val OpenId4VpTransactionDataBindingTest by matrixSuite {
    // OpenID4VP 1.0, IETF SD-JWT VC, "Transaction Data": "Wallets MUST reject requests with transaction data types that
    // have the `require_cryptographic_holder_binding` parameter set to `false`", also next to a query requiring it
    listOf(
        Triple("absent", "", false),
        Triple("true", ""","require_cryptographic_holder_binding": true""", false),
        Triple("false", ""","require_cryptographic_holder_binding": false""", true),
    ).asData(
        nameFn = { "Transaction data for a query with require_cryptographic_holder_binding ${it.first}" },
    ) - { (_, requireBinding, rejected) ->
        listOf(
            "[\"approval-credential\"]",
            "[\"approval-credential\", \"bound-credential\"]",
        ).asData(nameFn = { ids -> "credential_ids $ids" }) test { ids ->
            val encoded = """{
                "type": "https://cloudsignatureconsortium.org/2025/qes-approval",
                "credential_ids": $ids,
                "signatureQualifier": "eu_eidas_qes",
                "numSignatures": 1,
                "documentDigests": [{ "label": "Contract", "hash": "AQID" }],
                "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
            }""".trimIndent().encodeToByteArray().encodeToString(Base64UrlStrict)
            val input = """{
                "response_type": "vp_token",
                "client_id": "redirect_uri:https://verifier.example.org/response",
                "response_mode": "direct_post",
                "response_uri": "https://verifier.example.org/response",
                "state": "approval-state",
                "nonce": "approval-nonce",
                "dcql_query": {
                    "credentials": [{
                        "id": "approval-credential", "format": "dc+sd-jwt",
                        "meta": { "vct_values": ["AtomicAttribute2023"] }
                        $requireBinding
                    }, {
                        "id": "bound-credential", "format": "dc+sd-jwt",
                        "meta": { "vct_values": ["AtomicAttribute2023"] }
                    }]
                },
                "transaction_data": ["$encoded"]
            }""".trimIndent()
            val failure = OpenId4VpHolder().prepareAuthorizationResponse(input).exceptionOrNull()

            if (rejected) {
                failure.shouldBeInstanceOf<OAuth2Exception.InvalidTransactionData>()
                    .cause.shouldNotBeNull().message.shouldNotBeNull() shouldContain "cryptographic holder binding"
            } else {
                failure.shouldBeNull()
            }
        }
    }
}

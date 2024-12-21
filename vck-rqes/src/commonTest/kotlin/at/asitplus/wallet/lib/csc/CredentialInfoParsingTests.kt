package at.asitplus.wallet.lib.csc

import at.asitplus.rqes.CscCredentialListRequest
import at.asitplus.rqes.CscCredentialListResponse
import at.asitplus.rqes.collection_entries.CscAuthParameter
import at.asitplus.rqes.collection_entries.CscCertificateParameters
import at.asitplus.rqes.collection_entries.CscKeyParameters
import at.asitplus.rqes.enums.CertificateOptions
import at.asitplus.wallet.lib.data.vckJsonSerializer
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

class CredentialInfoParsingTests : FreeSpec({


    /**
     * Test vectors taken from CSC API v2.0.0.2
     * Placeholder values like ... are replaced by actual dummy values or removed
     */
    val credentialListRequestJson =
        """
            {
                "credentialInfo": true,
                "certificates": "chain",
                "certInfo": true,
                "authInfo": true
            }
        """.trimIndent().replace("\n", "").replace("\r", "").replace(" ", "")

    val credentialListResponseJson =
        """
        {
            "credentialIDs": [ "GX0112348" ]
            "credentialInfos":
            [
                {
                    "credentialID": "GX0112348",
                    "key":
                    {
                        "status": "enabled",
                        "algo": [ "1.2.840.113549.1.1.11", "1.2.840.113549.1.1.10" ],
                        "len": 2048
                    },
                    "cert":
                    {
                        "status": "valid",
                        "certificates":
                        [
                            "<Base64-encoded_X.509_end_entity_certificate>","<Base64-encoded_X.509_intermediate_CA_certificate>",
                            "<Base64-encoded_X.509_root_CA_certificate>"
                        ],
                        "issuerDN":"AAAAFFFF",
                        "serialNumber": "5AAC41CD8FA22B953640",
                        "subjectDN": "FFFFAAAA",
                        "validFrom": "20200101100000Z",
                        "validTo": "20230101095959Z"
                    },
                    "auth": 
                    {
                        "mode": "explicit",
                        "expression": "PIN AND OTP",
                        "objects": 
                        [
                            {
                                "type": "Password",
                                "id": "PIN",
                                "format": "N",
                                "label": "PIN",
                                "description": "Please enter the signature PIN"
                            },
                            {
                                "type": "Password",
                                "id": "OTP",
                                "format": "N",
                                "generator": "totp",
                                "label": "Mobile OTP",
                                "description": "Please enter the 6 digit code you received by
                                SMS"
                            }
                        ]
                    }
                    "multisign": 5,
                    "lang": "en-US"
                }
            ]
        }
    """.trimIndent().replace("\n", "").replace("\r", "").replace(" ", "")


    "credential/list request can be parsed" {
        val requestDecoded = vckJsonSerializer.decodeFromString<CscCredentialListRequest>(credentialListRequestJson)
        Napier.d("Parsed request is $requestDecoded")
        requestDecoded.credentialInfo shouldBe true
        requestDecoded.certificates shouldBe CertificateOptions.CHAIN

    }
    "credential/list response can be parsed" {
        val responseDecoded = vckJsonSerializer.decodeFromString<CscCredentialListResponse>(credentialListResponseJson)
        Napier.d("Parsed response is $responseDecoded")
        responseDecoded.credentialIDs.size shouldBe 1
        responseDecoded.credentialInfos shouldNotBe null
        responseDecoded.credentialInfos?.size shouldBe 1
        with(responseDecoded.credentialInfos?.first()) {
            this?.credentialID shouldBe responseDecoded.credentialIDs.first()
            this?.keyParameters?.status shouldBe CscKeyParameters.KeyStatusOptions.ENABLED
            this?.certParameters?.status shouldBe CscCertificateParameters.CertStatus.VALID
            this?.authParameters?.mode shouldBe CscAuthParameter.AuthMode.EXPLICIT
        }

    }
})
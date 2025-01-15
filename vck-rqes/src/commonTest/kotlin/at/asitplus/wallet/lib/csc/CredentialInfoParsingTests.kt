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
                            "MIIFajCCBPGgAwIBAgIQDNCovsYyz+ZF7KCpsIT7HDAKBggqhkjOPQQDAzBWMQsw
                            CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMTAwLgYDVQQDEydEaWdp
                            Q2VydCBUTFMgSHlicmlkIEVDQyBTSEEzODQgMjAyMCBDQTEwHhcNMjMwMjE0MDAw
                            MDAwWhcNMjQwMzE0MjM1OTU5WjBmMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2Fs
                            aWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEVMBMGA1UEChMMR2l0SHVi
                            LCBJbmMuMRMwEQYDVQQDEwpnaXRodWIuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0D
                            AQcDQgAEo6QDRgPfRlFWy8k5qyLN52xZlnqToPu5QByQMog2xgl2nFD1Vfd2Xmgg
                            nO4i7YMMFTAQQUReMqyQodWq8uVDs6OCA48wggOLMB8GA1UdIwQYMBaAFAq8CCkX
                            jKU5bXoOzjPHLrPt+8N6MB0GA1UdDgQWBBTHByd4hfKdM8lMXlZ9XNaOcmfr3jAl
                            BgNVHREEHjAcggpnaXRodWIuY29tgg53d3cuZ2l0aHViLmNvbTAOBgNVHQ8BAf8E
                            BAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMIGbBgNVHR8EgZMw
                            gZAwRqBEoEKGQGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRMU0h5
                            YnJpZEVDQ1NIQTM4NDIwMjBDQTEtMS5jcmwwRqBEoEKGQGh0dHA6Ly9jcmw0LmRp
                            Z2ljZXJ0LmNvbS9EaWdpQ2VydFRMU0h5YnJpZEVDQ1NIQTM4NDIwMjBDQTEtMS5j
                            cmwwPgYDVR0gBDcwNTAzBgZngQwBAgIwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3
                            dy5kaWdpY2VydC5jb20vQ1BTMIGFBggrBgEFBQcBAQR5MHcwJAYIKwYBBQUHMAGG
                            GGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBPBggrBgEFBQcwAoZDaHR0cDovL2Nh
                            Y2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VExTSHlicmlkRUNDU0hBMzg0MjAy
                            MENBMS0xLmNydDAJBgNVHRMEAjAAMIIBgAYKKwYBBAHWeQIEAgSCAXAEggFsAWoA
                            dwDuzdBk1dsazsVct520zROiModGfLzs3sNRSFlGcR+1mwAAAYZQ3Rv6AAAEAwBI
                            MEYCIQDkFq7T4iy6gp+pefJLxpRS7U3gh8xQymmxtI8FdzqU6wIhALWfw/nLD63Q
                            YPIwG3EFchINvWUfB6mcU0t2lRIEpr8uAHYASLDja9qmRzQP5WoC+p0w6xxSActW
                            3SyB2bu/qznYhHMAAAGGUN0cKwAABAMARzBFAiAePGAyfiBR9dbhr31N9ZfESC5G
                            V2uGBTcyTyUENrH3twIhAPwJfsB8A4MmNr2nW+sdE1n2YiCObW+3DTHr2/UR7lvU
                            AHcAO1N3dT4tuYBOizBbBv5AO2fYT8P0x70ADS1yb+H61BcAAAGGUN0cOgAABAMA
                            SDBGAiEAzOBr9OZ0+6OSZyFTiywN64PysN0FLeLRyL5jmEsYrDYCIQDu0jtgWiMI
                            KU6CM0dKcqUWLkaFE23c2iWAhYAHqrFRRzAKBggqhkjOPQQDAwNnADBkAjAE3A3U
                            3jSZCpwfqOHBdlxi9ASgKTU+wg0qw3FqtfQ31OwLYFdxh0MlNk/HwkjRSWgCMFbQ
                            vMkXEPvNvv4t30K6xtpG26qmZ+6OiISBIIXMljWnsiYR1gyZnTzIg3AQSw4Vmw=="
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
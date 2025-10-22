package at.asitplus.wallet.lib.rqes.csc

import at.asitplus.csc.CredentialInfoRequest
import at.asitplus.csc.CredentialListRequest
import at.asitplus.csc.CredentialListResponse
import at.asitplus.csc.collection_entries.AuthParameters
import at.asitplus.csc.collection_entries.CertificateParameters
import at.asitplus.csc.collection_entries.KeyParameters
import at.asitplus.csc.enums.CertificateOptions
import at.asitplus.wallet.lib.data.vckJsonSerializer
import com.benasher44.uuid.uuid4
import at.asitplus.testballoon.*
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldNotContain

val CredentialInfoParsingTests by testSuite {


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
        val decoded = vckJsonSerializer.decodeFromString<CredentialListRequest>(credentialListRequestJson)
        decoded.credentialInfo shouldBe true
        decoded.certificates shouldBe CertificateOptions.CHAIN

    }
    "credential/list response can be parsed" {
        val decoded = vckJsonSerializer.decodeFromString<CredentialListResponse>(credentialListResponseJson)

        decoded.credentialIDs.size shouldBe 1
        decoded.credentialInfos shouldNotBe null
        decoded.credentialInfos?.size shouldBe 1
        with(decoded.credentialInfos?.first().shouldNotBeNull()) {
            this.credentialID shouldBe decoded.credentialIDs.first()
            this.keyParameters.status shouldBe KeyParameters.KeyStatusOptions.ENABLED
            this.certParameters?.status shouldBe CertificateParameters.CertStatus.VALID
            this.authParameters?.mode shouldBe AuthParameters.AuthMode.EXPLICIT
        }
    }

    "CredentialInfoRequest default values are correctly encoded/decoded" {
        val request = CredentialInfoRequest(
            credentialID = uuid4().toString(),
        )
        val encoded = vckJsonSerializer.encodeToString(CredentialInfoRequest.serializer(), request)
        encoded.shouldNotContain("certificates")
        encoded.shouldNotContain("certInfo")
        encoded.shouldNotContain("authInfo")

        val decoded = vckJsonSerializer.decodeFromString<CredentialInfoRequest>(encoded)
        decoded.certificates shouldBe CertificateOptions.SINGLE
        decoded.authInfo shouldBe false
        decoded.certInfo shouldBe false
    }

    "CredentialListRequest default values are correctly encoded/decoded" {
        val request = CredentialListRequest()
        val encoded = vckJsonSerializer.encodeToString(CredentialListRequest.serializer(), request)
        encoded.shouldNotContain("certificates")
        encoded.shouldNotContain("certInfo")
        encoded.shouldNotContain("authInfo")

        val decoded = vckJsonSerializer.decodeFromString<CredentialListRequest>(encoded)
        decoded.certificates shouldBe CertificateOptions.SINGLE
        decoded.authInfo shouldBe false
        decoded.certInfo shouldBe false
    }
}
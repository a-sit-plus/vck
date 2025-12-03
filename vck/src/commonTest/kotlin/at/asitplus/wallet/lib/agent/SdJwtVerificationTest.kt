package at.asitplus.wallet.lib.agent

import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.SdJwtSigned
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.maps.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

/**
 * Verifies examples from [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html)
 */
val SdJwtVerificationTest by testSuite {

    "A.1. Simple structured SD-JWT" {
        val input = """
            eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBb
            IkM5aW5wNllvUmFFWFI0Mjd6WUpQN1FyazFXSF84YmR3T0FfWVVyVW5HUVUiLCAiS3Vl
            dDF5QWEwSElRdlluT1ZkNTloY1ZpTzlVZzZKMmtTZnFZUkJlb3d2RSIsICJNTWxkT0ZG
            ekIyZDB1bWxtcFRJYUdlcmhXZFVfUHBZZkx2S2hoX2ZfOWFZIiwgIlg2WkFZT0lJMnZQ
            TjQwVjd4RXhad1Z3ejd5Um1MTmNWd3Q1REw4Ukx2NGciLCAiWTM0em1JbzBRTExPdGRN
            cFhHd2pCZ0x2cjE3eUVoaFlUMEZHb2ZSLWFJRSIsICJmeUdwMFdUd3dQdjJKRFFsbjFs
            U2lhZW9iWnNNV0ExMGJRNTk4OS05RFRzIiwgIm9tbUZBaWNWVDhMR0hDQjB1eXd4N2ZZ
            dW8zTUhZS08xNWN6LVJaRVlNNVEiLCAiczBCS1lzTFd4UVFlVTh0VmxsdE03TUtzSVJU
            ckVJYTFQa0ptcXhCQmY1VSJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUu
            Y29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAiYWRkcmVz
            cyI6IHsiX3NkIjogWyI2YVVoelloWjdTSjFrVm1hZ1FBTzN1MkVUTjJDQzFhSGhlWnBL
            bmFGMF9FIiwgIkF6TGxGb2JrSjJ4aWF1cFJFUHlvSnotOS1OU2xkQjZDZ2pyN2ZVeW9I
            emciLCAiUHp6Y1Z1MHFiTXVCR1NqdWxmZXd6a2VzRDl6dXRPRXhuNUVXTndrclEtayIs
            ICJiMkRrdzBqY0lGOXJHZzhfUEY4WmN2bmNXN3p3Wmo1cnlCV3ZYZnJwemVrIiwgImNQ
            WUpISVo4VnUtZjlDQ3lWdWIyVWZnRWs4anZ2WGV6d0sxcF9KbmVlWFEiLCAiZ2xUM2hy
            U1U3ZlNXZ3dGNVVEWm1Xd0JUdzMyZ25VbGRJaGk4aEdWQ2FWNCIsICJydkpkNmlxNlQ1
            ZWptc0JNb0d3dU5YaDlxQUFGQVRBY2k0MG9pZEVlVnNBIiwgInVOSG9XWWhYc1poVkpD
            TkUyRHF5LXpxdDd0NjlnSkt5NVFhRnY3R3JNWDQiXX0sICJfc2RfYWxnIjogInNoYS0y
            NTYifQ.JwMde4aGprmyUSPPl4SB5Woe7cBBzxEYyIUiMApNTMZuYjdKjoJ09F1V5KQ0Q
            0d6AzvMCuZBEQSxuhJwQVZRMg
            ~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInJlZ2lvbiIsICJcdTZlMmZcdTUzM2E
            iXQ
            ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImNvdW50cnkiLCAiSlAiXQ
            ~
        """.trimIndent().replace("\n", "").replace(" ", "")

        val sdJwtSigned = SdJwtSigned.parseCatching(input).getOrThrow()
        val sdJwtDecoded = SdJwtDecoded(sdJwtSigned)
        val reconstructed = sdJwtDecoded.reconstructedJsonObject.shouldNotBeNull()
        sdJwtDecoded.validDisclosures.shouldNotBeEmpty()
        sdJwtSigned.serialize() shouldBe input

        val expected = """
            {
              "iss": "https://issuer.example.com",
              "iat": 1683000000,
              "exp": 1883000000,
              "address": {
                "region": "港区",
                "country": "JP"
              }
            }
        """.trimIndent()
        reconstructed shouldBe vckJsonSerializer.parseToJsonElement(expected)
    }

    "A.2. Complex Structured SD-JWT" {
        val input = """
            eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBb
            Ii1hU3puSWQ5bVdNOG9jdVFvbENsbHN4VmdncTEtdkhXNE90bmhVdFZtV3ciLCAiSUti
            cllObjN2QTdXRUZyeXN2YmRCSmpERFVfRXZRSXIwVzE4dlRScFVTZyIsICJvdGt4dVQx
            NG5CaXd6TkozTVBhT2l0T2w5cFZuWE9hRUhhbF94a3lOZktJIl0sICJpc3MiOiAiaHR0
            cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6
            IDE4ODMwMDAwMDAsICJ2ZXJpZmllZF9jbGFpbXMiOiB7InZlcmlmaWNhdGlvbiI6IHsi
            X3NkIjogWyI3aDRVRTlxU2N2REtvZFhWQ3VvS2ZLQkpwVkJmWE1GX1RtQUdWYVplM1Nj
            IiwgInZUd2UzcmFISUZZZ0ZBM3hhVUQyYU14Rno1b0RvOGlCdTA1cUtsT2c5THciXSwg
            InRydXN0X2ZyYW1ld29yayI6ICJkZV9hbWwiLCAiZXZpZGVuY2UiOiBbeyIuLi4iOiAi
            dFlKMFREdWN5WlpDUk1iUk9HNHFSTzV2a1BTRlJ4RmhVRUxjMThDU2wzayJ9XX0sICJj
            bGFpbXMiOiB7Il9zZCI6IFsiUmlPaUNuNl93NVpIYWFka1FNcmNRSmYwSnRlNVJ3dXJS
            czU0MjMxRFRsbyIsICJTXzQ5OGJicEt6QjZFYW5mdHNzMHhjN2NPYW9uZVJyM3BLcjdO
            ZFJtc01vIiwgIldOQS1VTks3Rl96aHNBYjlzeVdPNklJUTF1SGxUbU9VOHI4Q3ZKMGNJ
            TWsiLCAiV3hoX3NWM2lSSDliZ3JUQkppLWFZSE5DTHQtdmpoWDFzZC1pZ09mXzlsayIs
            ICJfTy13SmlIM2VuU0I0Uk9IbnRUb1FUOEptTHR6LW1oTzJmMWM4OVhvZXJRIiwgImh2
            RFhod21HY0pRc0JDQTJPdGp1TEFjd0FNcERzYVUwbmtvdmNLT3FXTkUiXX19LCAiX3Nk
            X2FsZyI6ICJzaGEtMjU2In0.QQlreqD-uUiutZfHPyqCh9zc6PFOOLz2HMvB7MrIxjUe
            U__0N-VzTlx_6cBIY2P7iE6uycx03OVxfihCFzXDrg
            ~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInRpbWUiLCAiMjAxMi0wNC0yM1QxODo
            yNVoiXQ
            ~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgeyJfc2QiOiBbIjl3cGpWUFd1RDdQSzB
            uc1FETDhCMDZsbWRnVjNMVnliaEh5ZFFwVE55TEkiLCAiRzVFbmhPQU9vVTlYXzZRTU5
            2ekZYanBFQV9SYy1BRXRtMWJHX3djYUtJayIsICJJaHdGcldVQjYzUmNacTl5dmdaMFh
            QYzdHb3doM08ya3FYZUJJc3dnMUI0IiwgIldweFE0SFNvRXRjVG1DQ0tPZURzbEJfZW1
            1Y1lMejJvTzhvSE5yMWJFVlEiXX1d
            ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgIm1ldGhvZCIsICJwaXBwIl0
            ~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgImdpdmVuX25hbWUiLCAiTWF4Il0
            ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImZhbWlseV9uYW1lIiwgIk1cdTAwZmN
            sbGVyIl0
            ~WyJ5MXNWVTV3ZGZKYWhWZGd3UGdTN1JRIiwgImFkZHJlc3MiLCB7ImxvY2FsaXR5Ijo
            gIk1heHN0YWR0IiwgInBvc3RhbF9jb2RlIjogIjEyMzQ0IiwgImNvdW50cnkiOiAiREU
            iLCAic3RyZWV0X2FkZHJlc3MiOiAiV2VpZGVuc3RyYVx1MDBkZmUgMjIifV0
            ~
        """.trimIndent().replace("\n", "").replace(" ", "")

        val sdJwtSigned = SdJwtSigned.parseCatching(input).getOrThrow()
        val sdJwtDecoded = SdJwtDecoded(sdJwtSigned)
        val reconstructed = sdJwtDecoded.reconstructedJsonObject.shouldNotBeNull()
        sdJwtDecoded.validDisclosures.shouldNotBeEmpty()
        sdJwtSigned.serialize() shouldBe input

        val expected = """
            {
              "iss": "https://issuer.example.com",
              "iat": 1683000000,
              "exp": 1883000000,
              "verified_claims": {
                "verification": {
                  "trust_framework": "de_aml",
                  "evidence": [
                    {
                      "method": "pipp"
                    }
                  ],
                  "time": "2012-04-23T18:25Z"
                },
                "claims": {
                  "given_name": "Max",
                  "family_name": "Müller",
                  "address": {
                    "locality": "Maxstadt",
                    "postal_code": "12344",
                    "country": "DE",
                    "street_address": "Weidenstraße 22"
                  }
                }
              }
            }
        """.trimIndent()

        reconstructed shouldBe vckJsonSerializer.parseToJsonElement(expected)
    }

    "A.3. SD-JWT-based Verifiable Credentials (SD-JWT VC)" {
        val input = """
            eyJhbGciOiAiRVMyNTYiLCAidHlwIjogInZjK3NkLWp3dCJ9.eyJfc2QiOiBbIjBIWm1
            uU0lQejMzN2tTV2U3QzM0bC0tODhnekppLWVCSjJWel9ISndBVGciLCAiOVpicGxDN1R
            kRVc3cWFsNkJCWmxNdHFKZG1lRU9pWGV2ZEpsb1hWSmRSUSIsICJJMDBmY0ZVb0RYQ3V
            jcDV5eTJ1anFQc3NEVkdhV05pVWxpTnpfYXdEMGdjIiwgIklFQllTSkdOaFhJbHJRbzU
            4eWtYbTJaeDN5bGw5WmxUdFRvUG8xN1FRaVkiLCAiTGFpNklVNmQ3R1FhZ1hSN0F2R1R
            yblhnU2xkM3o4RUlnX2Z2M2ZPWjFXZyIsICJodkRYaHdtR2NKUXNCQ0EyT3RqdUxBY3d
            BTXBEc2FVMG5rb3ZjS09xV05FIiwgImlrdXVyOFE0azhxM1ZjeUE3ZEMtbU5qWkJrUmV
            EVFUtQ0c0bmlURTdPVFUiLCAicXZ6TkxqMnZoOW80U0VYT2ZNaVlEdXZUeWtkc1dDTmc
            wd1RkbHIwQUVJTSIsICJ3elcxNWJoQ2t2a3N4VnZ1SjhSRjN4aThpNjRsbjFqb183NkJ
            DMm9hMXVnIiwgInpPZUJYaHh2SVM0WnptUWNMbHhLdUVBT0dHQnlqT3FhMXoySW9WeF9
            ZRFEiXSwgImlzcyI6ICJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsICJpYXQiOiA
            xNjgzMDAwMDAwLCAiZXhwIjogMTg4MzAwMDAwMCwgInZjdCI6ICJodHRwczovL2JtaS5
            idW5kLmV4YW1wbGUvY3JlZGVudGlhbC9waWQvMS4wIiwgImFnZV9lcXVhbF9vcl9vdmV
            yIjogeyJfc2QiOiBbIkZjOElfMDdMT2NnUHdyREpLUXlJR085N3dWc09wbE1Makh2UkM
            0UjQtV2ciLCAiWEx0TGphZFVXYzl6Tl85aE1KUm9xeTQ2VXNDS2IxSXNoWnV1cVVGS1N
            DQSIsICJhb0NDenNDN3A0cWhaSUFoX2lkUkNTQ2E2NDF1eWNuYzh6UGZOV3o4bngwIiw
            gImYxLVAwQTJkS1dhdnYxdUZuTVgyQTctRVh4dmhveHY1YUhodUVJTi1XNjQiLCAiazV
            oeTJyMDE4dnJzSmpvLVZqZDZnNnl0N0Fhb25Lb25uaXVKOXplbDNqbyIsICJxcDdaX0t
            5MVlpcDBzWWdETzN6VnVnMk1GdVBOakh4a3NCRG5KWjRhSS1jIl19LCAiX3NkX2FsZyI
            6ICJzaGEtMjU2IiwgImNuZiI6IHsiandrIjogeyJrdHkiOiAiRUMiLCAiY3J2IjogIlA
            tMjU2IiwgIngiOiAiVENBRVIxOVp2dTNPSEY0ajRXNHZmU1ZvSElQMUlMaWxEbHM3dkN
            lR2VtYyIsICJ5IjogIlp4amlXV2JaTVFHSFZXS1ZRNGhiU0lpcnNWZnVlY0NFNnQ0alQ
            5RjJIWlEifX19.Iwo8rkeneT9yPjiorofVRWvpVqVc9xiLCNAY-TLEuEAuslt8Ids1-1
            JNUln7FMICScXnakTscACf7o_DqDjl1w
            ~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiRXJpa2EiXQ
            ~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIk11c3Rlcm1
            hbm4iXQ
            ~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImJpcnRoZGF0ZSIsICIxOTYzLTA4LTE
            yIl0
            ~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInNvdXJjZV9kb2N1bWVudF90eXBlIiw
            gImlkX2NhcmQiXQ
            ~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInN0cmVldF9hZGRyZXNzIiwgIkhlaWR
            lc3RyYVx1MDBkZmUgMTciXQ
            ~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImxvY2FsaXR5IiwgIktcdTAwZjZsbiJ
            d
            ~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgInBvc3RhbF9jb2RlIiwgIjUxMTQ3Il0
            ~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgImNvdW50cnkiLCAiREUiXQ
            ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImFkZHJlc3MiLCB7Il9zZCI6IFsiWEZ
            jN3pYUG03enpWZE15d20yRXVCZmxrYTVISHF2ZjhVcF9zek5HcXZpZyIsICJiZDFFVnp
            nTm9wVWs0RVczX2VRMm4zX05VNGl1WE9IdjlYYkdITjNnMVRFIiwgImZfRlFZZ3ZRV3Z
            5VnFObklYc0FSbE55ZTdZR3A4RTc3Z1JBamFxLXd2bnciLCAidjRra2JfcFAxamx2VWJ
            TanR5YzVicWNXeUEtaThYTHZoVllZN1pUMHRiMCJdfV0
            ~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIm5hdGlvbmFsaXRpZXMiLCBbIkRFIl1d
            ~WyI1YlBzMUlxdVpOYTBoa2FGenp6Wk53IiwgImdlbmRlciIsICJmZW1hbGUiXQ
            ~WyI1YTJXMF9OcmxFWnpmcW1rXzdQcS13IiwgImJpcnRoX2ZhbWlseV9uYW1lIiwgIkd
            hYmxlciJd
            ~WyJ5MXNWVTV3ZGZKYWhWZGd3UGdTN1JRIiwgImxvY2FsaXR5IiwgIkJlcmxpbiJd
            ~WyJIYlE0WDhzclZXM1FEeG5JSmRxeU9BIiwgInBsYWNlX29mX2JpcnRoIiwgeyJfc2Q
            iOiBbIldwaEhvSUR5b1diQXBEQzR6YnV3UjQweGwweExoRENfY3Y0dHNTNzFyRUEiXSw
            gImNvdW50cnkiOiAiREUifV0
            ~WyJDOUdTb3VqdmlKcXVFZ1lmb2pDYjFBIiwgImFsc29fa25vd25fYXMiLCAiU2Nod2V
            zdGVyIEFnbmVzIl0
            ~WyJreDVrRjE3Vi14MEptd1V4OXZndnR3IiwgIjEyIiwgdHJ1ZV0
            ~WyJIM28xdXN3UDc2MEZpMnllR2RWQ0VRIiwgIjE0IiwgdHJ1ZV0
            ~WyJPQktsVFZsdkxnLUFkd3FZR2JQOFpBIiwgIjE2IiwgdHJ1ZV0
            ~WyJNMEpiNTd0NDF1YnJrU3V5ckRUM3hBIiwgIjE4IiwgdHJ1ZV0
            ~WyJEc210S05ncFY0ZEFIcGpyY2Fvc0F3IiwgIjIxIiwgdHJ1ZV0
            ~WyJlSzVvNXBIZmd1cFBwbHRqMXFoQUp3IiwgIjY1IiwgZmFsc2Vd~
        """.trimIndent().replace("\n", "").replace(" ", "")

        val sdJwtSigned = SdJwtSigned.parseCatching(input).getOrThrow()
        val sdJwtDecoded = SdJwtDecoded(sdJwtSigned)
        val reconstructed = sdJwtDecoded.reconstructedJsonObject.shouldNotBeNull()
        sdJwtDecoded.validDisclosures.shouldNotBeEmpty()
        sdJwtSigned.serialize() shouldBe input

        val expected = """
            {
              "given_name": "Erika",
              "family_name": "Mustermann",
              "birthdate": "1963-08-12",
              "source_document_type": "id_card",
              "address": {
                "street_address": "Heidestraße 17",
                "locality": "Köln",
                "postal_code": "51147",
                "country": "DE"
              },
              "nationalities": [
                "DE"
              ],
              "gender": "female",
              "birth_family_name": "Gabler",
              "place_of_birth": {
                "locality": "Berlin",
                "country": "DE"
              },
              "also_known_as": "Schwester Agnes",
              "age_equal_or_over": {
                "12": true,
                "14": true,
                "16": true,
                "18": true,
                "21": true,
                "65": false
              },
            
              "iss": "https://issuer.example.com",
              "iat": 1683000000,
              "exp": 1883000000,
              "vct": "https://bmi.bund.example/credential/pid/1.0",
              "cnf": { 
                "jwk": { 
                    "kty": "EC",
                    "crv": "P-256",
                    "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
                    "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
                }
              }
            }
        """.trimIndent()
        reconstructed shouldBe vckJsonSerializer.parseToJsonElement(expected)
    }

    "A.4. W3C Verifiable Credentials Data Model v2.0" {
        val input = """
            eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJAY29udGV4
            dCI6IFsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCAiaHR0
            cHM6Ly93M2lkLm9yZy92YWNjaW5hdGlvbi92MSJdLCAidHlwZSI6IFsiVmVyaWZpYWJs
            ZUNyZWRlbnRpYWwiLCAiVmFjY2luYXRpb25DZXJ0aWZpY2F0ZSJdLCAiaXNzdWVyIjog
            Imh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlzc3VhbmNlRGF0ZSI6ICIyMDIz
            LTAyLTA5VDExOjAxOjU5WiIsICJleHBpcmF0aW9uRGF0ZSI6ICIyMDI4LTAyLTA4VDEx
            OjAxOjU5WiIsICJuYW1lIjogIkNPVklELTE5IFZhY2NpbmF0aW9uIENlcnRpZmljYXRl
            IiwgImRlc2NyaXB0aW9uIjogIkNPVklELTE5IFZhY2NpbmF0aW9uIENlcnRpZmljYXRl
            IiwgImNyZWRlbnRpYWxTdWJqZWN0IjogeyJfc2QiOiBbIjFWX0stOGxEUThpRlhCRlhi
            Wlk5ZWhxUjRIYWJXQ2k1VDB5Ykl6WlBld3ciLCAiSnpqTGd0UDI5ZFAtQjN0ZDEyUDY3
            NGdGbUsyenk4MUhNdEJnZjZDSk5XZyIsICJSMmZHYmZBMDdaX1lsa3FtTlp5bWExeHl5
            eDFYc3RJaVM2QjFZYmwySlo0IiwgIlRDbXpybDdLMmdldl9kdTdwY01JeXpSTEhwLVll
            Zy1GbF9jeHRyVXZQeGciLCAiVjdrSkJMSzc4VG1WRE9tcmZKN1p1VVBIdUtfMmNjN3la
            UmE0cVYxdHh3TSIsICJiMGVVc3ZHUC1PRERkRm9ZNE5semxYYzN0RHNsV0p0Q0pGNzVO
            dzhPal9nIiwgInpKS19lU01YandNOGRYbU1aTG5JOEZHTTA4ekozX3ViR2VFTUotNVRC
            eTAiXSwgInZhY2NpbmUiOiB7Il9zZCI6IFsiMWNGNWhMd2toTU5JYXFmV0pyWEk3Tk1X
            ZWRMLTlmNlkyUEE1MnlQalNaSSIsICJIaXk2V1d1ZUxENWJuMTYyOTh0UHY3R1hobWxk
            TURPVG5CaS1DWmJwaE5vIiwgIkxiMDI3cTY5MWpYWGwtakM3M3ZpOGViT2o5c214M0Mt
            X29nN2dBNFRCUUUiXSwgInR5cGUiOiAiVmFjY2luZSJ9LCAicmVjaXBpZW50IjogeyJf
            c2QiOiBbIjFsU1FCTlkyNHEwVGg2T0d6dGhxLTctNGw2Y0FheHJZWE9HWnBlV19sbkEi
            LCAiM256THE4MU0yb04wNndkdjFzaEh2T0VKVnhaNUtMbWREa0hFREpBQldFSSIsICJQ
            bjFzV2kwNkc0TEpybm4tX1JUMFJiTV9IVGR4blBKUXVYMmZ6V3ZfSk9VIiwgImxGOXV6
            ZHN3N0hwbEdMYzcxNFRyNFdPN01HSnphN3R0N1FGbGVDWDRJdHciXSwgInR5cGUiOiAi
            VmFjY2luZVJlY2lwaWVudCJ9LCAidHlwZSI6ICJWYWNjaW5hdGlvbkV2ZW50In0sICJf
            c2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJj
            cnYiOiAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxp
            bERsczd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVj
            Q0U2dDRqVDlGMkhaUSJ9fX0.OZomvwO8iw4db89MYCeeomBVStXkT6u7G7FkicPWZnd2
            _hGgr0l_u1NHgPVocuOt-m32Uu6kwtPmYFxKk0AOeA
            ~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgIm9yZGVyIiwgIjMvMyJd
            ~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImRhdGVPZlZhY2NpbmF0aW9uIiwgIjI
            wMjEtMDYtMjNUMTM6NDA6MTJaIl0
            ~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImF0Y0NvZGUiLCAiSjA3QlgwMyJd
            ~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgIm1lZGljaW5hbFByb2R1Y3ROYW1lIiw
            gIkNPVklELTE5IFZhY2NpbmUgTW9kZXJuYSJd
            ~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9
            .eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV
            4YW1wbGUub3JnIiwgImlhdCI6IDE3NDg1MzcyNDQsICJzZF9oYXNoIjogIklvV1VIOTF
            sbGYzWEVybDQyYlEzc3hfNTNWMW8xdWpDejA4aERxSEs3RGsifQ
            .n0vzyIwCFMDVauEaeJIWEKZZchxXMpXTQewHgAkARbOSZxB09IbXXtHfpoGqO_BtNFN
            2lShJEIQBGyc-XpHigA
        """.trimIndent().replace("\n", "").replace(" ", "")

        val sdJwtSigned = SdJwtSigned.parseCatching(input).getOrThrow()
        val sdJwtDecoded = SdJwtDecoded(sdJwtSigned)
        val reconstructed = sdJwtDecoded.reconstructedJsonObject.shouldNotBeNull()
        sdJwtDecoded.validDisclosures.shouldNotBeEmpty()
        sdJwtSigned.serialize() shouldBe input

        val expected = """
            {
              "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/vaccination/v1"
              ],
              "type": [
                "VerifiableCredential",
                "VaccinationCertificate"
              ],
              "issuer": "https://example.com/issuer",
              "issuanceDate": "2023-02-09T11:01:59Z",
              "expirationDate": "2028-02-08T11:01:59Z",
              "name": "COVID-19 Vaccination Certificate",
              "description": "COVID-19 Vaccination Certificate",
              "credentialSubject": {
                "vaccine": {
                  "type": "Vaccine",
                  "atcCode": "J07BX03",
                  "medicinalProductName": "COVID-19 Vaccine Moderna"
                },
                "recipient": {
                  "type": "VaccineRecipient"
                },
                "type": "VaccinationEvent",
                "order": "3/3",
                "dateOfVaccination": "2021-06-23T13:40:12Z"
              },
              "cnf": {
                "jwk": {
                  "kty": "EC",
                  "crv": "P-256",
                  "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
                  "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
                }
              }
            }
        """.trimIndent()
        reconstructed shouldBe vckJsonSerializer.parseToJsonElement(expected)
    }

}
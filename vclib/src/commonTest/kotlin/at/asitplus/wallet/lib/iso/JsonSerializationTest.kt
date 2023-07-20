package at.asitplus.wallet.lib.iso

import at.asitplus.wallet.lib.jws.JwsSigned
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldNotBe

class JsonSerializationTest : FreeSpec({

    beforeSpec {
        Napier.base(DebugAntilog())
    }

    // from ISO/IEC 18013-5:2021(E), D4.2.1.1, page 120
    "Server Request" {
        val input = """
            {
              "version": "1.0",
              "token": "0w4P4mDP_yxnB4iL4KsYwQ",
              "docRequests": [{
                "docType": "org.iso.18013.5.1.mDL",
                "nameSpaces": {
                  "org.iso.18013.5.1": {
                    "family_name": true,
                    "document_number": true,
                    "driving_privileges": true,
                    "issue_date": true,
                    "expiry_date": true,
                    "portrait": false
                  }
                }
              }]
            }
        """.trimIndent()

        val deserialized = ServerRequest.deserialize(input)
        deserialized.shouldNotBeNull()
        println(deserialized)
    }

    // from ISO/IEC 18013-5:2021(E), D4.2.1.2, page 121
    "Server Response" {
        val input = """
            {
              "version": "1.0",
              "documents":
              ["eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlCN3pDQ0FaYWdBd0lCQWdJVUZhcDZiTHFR
              T0h0NGROZXNvUy9EYm9IU1BjMHdDZ1lJS29aSXpqMEVBd0l3SXpFVU1CSUdBMVVFQXd3TGRYUnZjR2xoSUdsaFkyRX
              hDekFKQmdOVkJBWVRBbFZUTUI0WERUSXdNVEF3TVRBd01EQXdNRm9YRFRJeE1UQXdNVEF3TURBd01Gb3dJakVUTUJ
              FR0ExVUVBd3dLZFhSdmNHbGhJR3AzY3pFTE1Ba0dBMVVFQmhNQ1ZWTXdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9Q
              UU1CQndOQ0FBUzRLYTVzUUtCOHQ2b0JJMjM4bXRkOFdRaTdoRWhsNE1YQ21jU0V5a3hUbzdjNUVndHRHQnkxRm5yS
              1BXQlo4MXFJcXpubzNQdDNyRVhpSUw3cHhHUERvNEdvTUlHbE1CNEdBMVVkRWdRWE1CV0JFMlY0WVcxd2JHVkFaWGh
              oYlhCc1pTNWpiMjB3SEFZRFZSMGZCQlV3RXpBUm9BK2dEWUlMWlhoaGJYQnNaUzVqYjIwd0hRWURWUjBPQkJZRUZPR
              3RtWFAxUmZxdjhmeW9BcFBUVyswa2ttc3BNQjhHQTFVZEl3UVlNQmFBRkZUNkk0T2dUQ2pnMlRCNUltSElERWlCMH
              NBTE1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBVkJnTlZIU1VCQWY4RUN6QUpCZ2NvZ1l4ZEJRRURNQW9HQ0NxR1NNNDlC
              QU1DQTBjQU1FUUNJQ1Q5OU5zREsxeGhlWFcyTTNVcmVzNzhOYlVuNGFyRjh6K1RDZ0VvWlF3VkFpQjRiL1Uxazg4V0
              hEK01sZmxiM0NkSHpQd1RoNmZGYVAycGFMVnZRZHJsZHc9PSJdfQ.eyJkb2N0eXBlIjoib3JnLmlzby4xODAxMy41L
              jEubURMIiwibmFtZXNwYWNlcyI6eyJvcmcuaXNvLjE4MDEzLjUuMSI6eyJmYW1pbHlfbmFtZSI6IkRvZSIsImdpdmV
              uX25hbWUiOiJKYW5lIiwiaXNzdWVfZGF0ZSI6IjIwMTktMTAtMjAiLCJleHBpcnlfZGF0ZSI6IjIwMjQtMTAtMjAiL
              CJkb2N1bWVudF9udW1iZXIiOiIxMjM0NTY3ODkiLCJwb3J0cmFpdCI6Il85al80QUFRU2taSlJnQUJBUUVBa0FDUUF
              BRF8yd0JEQUJNTkRoRU9EQk1SRHhFVkZCTVhIVEFmSFJvYUhUb3FMQ013UlQxSlIwUTlRMEZNVm0xZFRGRm9Va0ZEW
              DRKZ2FIRjFlM3g3U2x5R2tJVjNqMjE0ZTNiXzJ3QkRBUlFWRlIwWkhUZ2ZIemgyVDBOUGRuWjJkbloyZG5aMmRuWjJ
              kbloyZG5aMmRuWjJkbloyZG5aMmRuWjJkbloyZG5aMmRuWjJkbloyZG5aMmRuWjJkbmJfd0FBUkNBQVlBR1FEQVNJQ
              UFoRUJBeEVCXzhRQUd3QUFBd0VBQXdFQUFBQUFBQUFBQUFBQUFBVUdCQUVDQXdmX3hBQXlFQUFCQXdNREFnVUNBd2t
              BQUFBQUFBQUJBZ01FQUFVUkJoSWhFekVVRlZGaGNTSkJCNEdoRmpWQ1VuT1Jzc0h4XzhRQUZRRUJBUUFBQUFBQUFBQ
              UFBQUFBQUFBQUFBSF94QUFhRVFFQkFRQURBUUFBQUFBQUFBQUFBQUFBQVVFUklURmhfOW9BREFNQkFBSVJBeEVBUHd
              DbHU5NGkyaU1weDlhU3ZIME5BX1VzLXdfM1hucC04LWR3bHlPaDBOcmhSdDM3czhBNXpnZXRLOVI2ZmpMYnVOMGRVd
              GJ2U3loUFpLU0FCbjM3VWZoXy01WF9BT3VmOFUwaFhlWnE4SW5PUkxmYjNweTJpUW9vT08zZkdBZVBldDFpMUJIdlR
              ibXhDbVhXdVZvVWM0SHFEVWxia3pKMV9tdTZkY0VVRUVxTHBCQkJQcGc5X3dCUFd2WFRTMHRNM21NdENfSDlGWks5M
              lJ4a0VmT1RUQy1tcjJ0VWwxMFFiYzlLWmE1VzZGWUFIcndEeDg0cDNaN3ZIdkVQeEVmY25hZHEwcTdwTlRlaHVuNVB
              jTjJPX3dCWHh0XzdYaG9aaFVxRGRZNVVVb2RRbEc3R2NFaFF6UU43enJDTGJYMHN4MjB6Rl94N1hNQlB0bkJ5YWNYR
              zRNVzJDdVZKSkNFanNPU1Q5Z0tnZFZXZU5abHcyWTI0bFNWRmExSEpVY2l2b1Q2bzZZNDhXV2cyZUQxY1lfV21HcG4
              5dHlrSWRkdEw2SXF6aEx1N3Y4Y1lQOTZxWXo2SlVkdDlvNWJjU0ZKUHNhaTlZUnBhb3FKREx6Q3JRZ3A2YlRKQXh4a
              lBBeC1wNzB5YTFWQWdXcUFwVWQ5S0hXeUVJYkFWdDJuYmpKSXBnMzZpdm9zYkRUblE2Nm5GRklUdjI0d09fWTBsamE
              4OFJKYVo4dTI5UllUbnI1eGs0X2xybS1zbzFLeEFreDVrZU1qbmFpU29KVVNWQWRobjBySGMzcnJwbTV4MUt1VHMxd
              DNrb1huQndlUmdrNC1SU2U5bFhsRmNBNUdhS0p5ejNLSjQtM3Z4ZF9UNnFDbmRqT1B5ckpwLXplU1FseC12MTl6aFh
              1MmJjY0FZeGstbEZGRkxKT2prLU1YSnQxd2VnbGVkd1NNOV9zQ0NPUGF0MWkwNUdzd2NVbGFubm5CdFV0UXh4NkFVV
              VVDNV9SU2VzNllOeGVpTXU4TGFDU1FSNmR4eDg1cDNaclJIczBUb1I5eXNuY3RhdTZqUlJRWWRRNmI4OGVaYzhWME9
              rQ01kUGRuUDVpbVZ4dHpGeWhLaXlRU2hYM0hkSjlSUlJUNEowYUlVVUpZY3V6Nm9xVlpETzNnZkhPTTlfdFZQRGl0U
              W9yY2RoTzF0c1lBb29vRjE5MF9HdmFFRnhTbW5rY0pjVHp4NkVmY1ZoaWFQU21hM0p1TTk2ZXB2RzFLeGdjZGdjazV
              IdFJSU0Nsb29vb1BfMlEiLCJkcml2aW5nX3ByaXZpbGVnZXMiOlt7InZlaGljbGVfY2F0ZWdvcnlfY29kZSI6IkEiL
              CJpc3N1ZV9kYXRlIjoiMjAxOC0wOC0wOSIsImV4cGlyeV9kYXRlIjoiMjAyNC0xMC0yMCJ9LHsidmVoaWNsZV9jYXR
              lZ29yeV9jb2RlIjoiQiIsImlzc3VlX2RhdGUiOiIyMDE3LTAyLTIzIiwiZXhwaXJ5X2RhdGUiOiIyMDI0LTEwLTIwI
              n1dfX0sImlhdCI6MTYwOTg1NTIwMCwiZXhwIjoxNjA5ODU1MzIwfQ.JRjQgYpNthh52j3xQ1f6tkoKRBsF8YwH6NlK
              Yg2n_pyayOoQyrRPO0aPBeVJ5lgKBzLumjamuvr3C824R_RYHQ"
              ]
            }
        """.trimIndent()

        val deserialized = ServerResponse.deserialize(input)
        deserialized.shouldNotBeNull()
        println(deserialized)

        val payload = deserialized.documents.first()
        val jws = JwsSigned.parse(payload)
        jws.shouldNotBeNull()

        val mdl = MobileDrivingLicenceJws.deserialize(jws.payload.decodeToString())
        mdl.shouldNotBeNull()
        println(mdl)
    }

})

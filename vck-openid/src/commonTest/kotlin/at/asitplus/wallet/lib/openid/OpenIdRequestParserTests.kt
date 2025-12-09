package at.asitplus.wallet.lib.openid

import at.asitplus.dcapi.request.DCAPIWalletRequest
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlinx.serialization.json.JsonObject


val OpenIdRequestParserTests by testSuite {

    // https://verifier.funke.wwwallet.org/verifier/public/definitions/presentation-request/PID
    val jws = """
            eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlFQURDQ0F1aWdBd0lCQWdJVVFpVk9NVXllNS9OWGtUbWhnZ0RzS1hHNE9QZ3dEUVlKS29aSWh2
            Y05BUUVMQlFBd2NURUxNQWtHQTFVRUJoTUNSMUl4RHpBTkJnTlZCQWdNQmtGMGFHVnVjekVRTUE0R0ExVUVCd3dIU1d4c2FYTnBZVEVPTUF3
            R0ExVUVDZ3dGUjFWdVpYUXhFVEFQQmdOVkJBc01DRWxrWlc1MGFYUjVNUnd3R2dZRFZRUUREQk4zZDNkaGJHeGxkQzFsYm5SbGNuQnlhWE5s
            TUI0WERUSTBNRGt5T1RFMU5EZ3dPVm9YRFRJMU1Ea3lPVEUxTkRnd09Wb3djVEVMTUFrR0ExVUVCaE1DUjFJeER6QU5CZ05WQkFnTUJrRjBh
            R1Z1Y3pFUU1BNEdBMVVFQnd3SFNXeHNhWE5wWVRFT01Bd0dBMVVFQ2d3RlIxVnVaWFF4RVRBUEJnTlZCQXNNQ0Vsa1pXNTBhWFI1TVJ3d0dn
            WURWUVFEREJOM2QzZGhiR3hsZEMxbGJuUmxjbkJ5YVhObE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBeDFJ
            aHZEa1dYY2NackhKcjU0NC9rTG5WSXgzbDg1blgrcmxxRHpCWGVHdHFNRDVFWkV3YXNMU0JiMHRsQXlsZnVVU1BrNGFJcDBnTDhweUdET3Np
            dFJUWmtwNk5yL051OTgyTTV4bnk3N202NW1CcHFGQ0x0UlBvTU0vQlpJbzJ0YnBFY3FDU3Y5Z2RwTVhKRE9ldDV6UzcrT3NzVDRBdTZYYjJL
            azMwNDlFb2d0WjAyaGtFc3czRktqbzB4ZUR4cFRBNW1yaWI3Zzlod1RUOTcxdmlRSFZKUHdtYXk4ODNFemxtZm42KytLbllFNFY2eWNYZ3A1
            Q2Y3RFJZQVNmdTdYZkM3RXpqVHJ3ZGJzNFlJZjc0MGw3Q0lOejd6U2V1dEwrdWI3UnN4M0twQ0paM2p4Tzh4TDFhcnVubmsxZlZ1dUFjR3JZ
            VjAwOWlkekUwWTJRSzl3SURBUUFCbzRHUE1JR01NR3NHQTFVZEVRUmtNR0tDSFhkaGJHeGxkQzFsYm5SbGNuQnlhWE5sTFdWb2FXTXRhWE56
            ZFdWeWdpQjNZV3hzWlhRdFpXNTBaWEp3Y21selpTMWthWEJzYjIxaExXbHpjM1ZsY29JZmQyRnNiR1YwTFdWdWRHVnljSEpwYzJVdFlXTnRa
            UzEyWlhKcFptbGxjakFkQmdOVkhRNEVGZ1FVKzhNODZORU51RSt4RnhWTnk5V3daNTFHNld3d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFM
            YTVmWUQzaU5PVDUrV29oeHVXNVM2WVk0czllVVBjMk1jbURYd2duczcrOE1McVpnWmNHbHQ0RTExWWpNa0VHK1VsajJPMkpOYmJnSlorRXlu
            ekNCNmIvMFdLVi91WjV4aE5hN3F3aitPdDNPTkdIZy9lUXVkOWZUd0N0YU5VSzRnaUlUZXRJSVhXQllNQUYrall4K3FkNUFWaWdMVXViZHo0
            S3ZKU05WOU04ZU93TmJFckVXMmt2TzBSS0thMThtMkZZbWhXUXRORG9odFlsMTlqVHA3TGtwa0NxUzNkQXZxb1hTbGdIaXlWYVpCOUo2NGZH
            OThORzFuUkhtVVpDaFhKTDVGTmxGS2VLc3R1Ulk0UkQwbVgrbENIUUlTc2dYVjRLK0xjWEdyNEpQTlBIdzZWSFM1akU0bll4bFkvT2FJV3Vz
            b0gxVXVESUYyeG5CamtSZ3c9Il19.
            eyJyZXNwb25zZV91cmkiOiJodHRwczovL3ZlcmlmaWVyLmZ1bmtlLnd3d2FsbGV0Lm9yZy92ZXJpZmljYXRpb24vZGlyZWN0X3Bvc3QiLCJh
            dWQiOiJodHRwczovL3NlbGYtaXNzdWVkLm1lL3YyIiwiaXNzIjoidmVyaWZpZXIuZnVua2Uud3d3YWxsZXQub3JnIiwiY2xpZW50X2lkX3Nj
            aGVtZSI6Ing1MDlfc2FuX2RucyIsImNsaWVudF9pZCI6InZlcmlmaWVyLmZ1bmtlLnd3d2FsbGV0Lm9yZyIsInJlc3BvbnNlX3R5cGUiOiJ2
            cF90b2tlbiIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJzdGF0ZSI6ImYyYWQ3YWFiLThiMDQtNGU2NS1iYmJmLTI4MDg1
            ODNkMTlhZiIsIm5vbmNlIjoiN2Q1MWJjNGEtOThjNS00YjdjLTg1OGQtY2E3MGQ0Y2NiOGY3IiwicHJlc2VudGF0aW9uX2RlZmluaXRpb24i
            OnsiaWQiOiJQSUQiLCJ0aXRsZSI6IlNELUpXVCBQSUQiLCJkZXNjcmlwdGlvbiI6IlJlcXVpcmVkIEZpZWxkczogQ3JlZGVudGlhbCB0eXBl
            LCBHaXZlbiBOYW1lLCBGYW1pbHkgTmFtZSwgQmlydGhkYXRlLCBQbGFjZSBvZiBCaXJ0aCwgQmlydGggWWVhciwgQWdlIGluIFllYXJzLCBG
            YW1pbHkgTmFtZSBhdCBCaXJ0aCwgTmF0aW9uYWxpdGllcywgQWRkcmVzcywgSXNzdWluZyBDb3VudHJ5LCBJc3N1aW5nIEF1dGhvcml0eSIs
            ImlucHV0X2Rlc2NyaXB0b3JzIjpbeyJpZCI6IlZlcmlmaWFibGVJZCIsIm5hbWUiOiJQSUQiLCJwdXJwb3NlIjoiUHJlc2VudCB5b3VyIFNE
            LUpXVCBQSUQiLCJmb3JtYXQiOnsidmMrc2Qtand0Ijp7InNkLWp3dF9hbGdfdmFsdWVzIjpbIkVTMjU2Il0sImtiLWp3dF9hbGdfdmFsdWVz
            IjpbIkVTMjU2Il19fSwiY29uc3RyYWludHMiOnsibGltaXRfZGlzY2xvc3VyZSI6InJlcXVpcmVkIiwiZmllbGRzIjpbeyJuYW1lIjoiQ3Jl
            ZGVudGlhbCB0eXBlIiwicGF0aCI6WyIkLnZjdCJdLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsImVudW0iOlsiaHR0cHM6Ly9leGFtcGxl
            LmJtaS5idW5kLmRlL2NyZWRlbnRpYWwvcGlkLzEuMCIsInVybjpldS5ldXJvcGEuZWMuZXVkaTpwaWQ6MSJdfSwiaW50ZW50X3RvX3JldGFp
            biI6ZmFsc2V9LHsibmFtZSI6IkdpdmVuIE5hbWUiLCJwYXRoIjpbIiQuZ2l2ZW5fbmFtZSJdLCJmaWx0ZXIiOnt9LCJpbnRlbnRfdG9fcmV0
            YWluIjpmYWxzZX0seyJuYW1lIjoiRmFtaWx5IE5hbWUiLCJwYXRoIjpbIiQuZmFtaWx5X25hbWUiXSwiZmlsdGVyIjp7fSwiaW50ZW50X3Rv
            X3JldGFpbiI6ZmFsc2V9LHsibmFtZSI6IkJpcnRoZGF0ZSIsInBhdGgiOlsiJC5iaXJ0aGRhdGUiXSwiZmlsdGVyIjp7fSwiaW50ZW50X3Rv
            X3JldGFpbiI6ZmFsc2V9LHsibmFtZSI6IlBsYWNlIG9mIEJpcnRoIiwicGF0aCI6WyIkLnBsYWNlX29mX2JpcnRoLmxvY2FsaXR5Il0sImZp
            bHRlciI6e30sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7Im5hbWUiOiJCaXJ0aCBZZWFyIiwicGF0aCI6WyIkLmFnZV9iaXJ0aF95ZWFy
            Il0sImZpbHRlciI6e30sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7Im5hbWUiOiJBZ2UgaW4gWWVhcnMiLCJwYXRoIjpbIiQuYWdlX2lu
            X3llYXJzIl0sImZpbHRlciI6e30sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7Im5hbWUiOiJGYW1pbHkgTmFtZSBhdCBCaXJ0aCIsInBh
            dGgiOlsiJC5iaXJ0aF9mYW1pbHlfbmFtZSJdLCJmaWx0ZXIiOnt9LCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJuYW1lIjoiTmF0aW9u
            YWxpdGllcyIsInBhdGgiOlsiJC5uYXRpb25hbGl0aWVzIl0sImZpbHRlciI6e30sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7Im5hbWUi
            OiJBZGRyZXNzIC0gTG9jYWxpdHkiLCJwYXRoIjpbIiQuYWRkcmVzcy5sb2NhbGl0eSJdLCJmaWx0ZXIiOnt9LCJpbnRlbnRfdG9fcmV0YWlu
            IjpmYWxzZX0seyJuYW1lIjoiQWRkcmVzcyAtIENvdW50cnkiLCJwYXRoIjpbIiQuYWRkcmVzcy5jb3VudHJ5Il0sImZpbHRlciI6e30sImlu
            dGVudF90b19yZXRhaW4iOmZhbHNlfSx7Im5hbWUiOiJBZGRyZXNzIC0gUG9zdGFsIENvZGUiLCJwYXRoIjpbIiQuYWRkcmVzcy5wb3N0YWxf
            Y29kZSJdLCJmaWx0ZXIiOnt9LCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJuYW1lIjoiQWRkcmVzcyAtIFN0cmVldCBBZGRyZXNzIiwi
            cGF0aCI6WyIkLmFkZHJlc3Muc3RyZWV0X2FkZHJlc3MiXSwiZmlsdGVyIjp7fSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsibmFtZSI6
            Iklzc3VpbmcgQ291bnRyeSIsInBhdGgiOlsiJC5pc3N1aW5nX2NvdW50cnkiXSwiZmlsdGVyIjp7fSwiaW50ZW50X3RvX3JldGFpbiI6ZmFs
            c2V9LHsibmFtZSI6Iklzc3VpbmcgQXV0aG9yaXR5IiwicGF0aCI6WyIkLmlzc3VpbmdfYXV0aG9yaXR5Il0sImZpbHRlciI6e30sImludGVu
            dF90b19yZXRhaW4iOmZhbHNlfSx7Im5hbWUiOiJBZ2UgRXF1YWwgb3Igb3ZlciAxMiIsInBhdGgiOlsiJC5hZ2VfZXF1YWxfb3Jfb3Zlci4x
            MiJdLCJmaWx0ZXIiOnt9LCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJuYW1lIjoiQWdlIEVxdWFsIG9yIG92ZXIgMTQiLCJwYXRoIjpb
            IiQuYWdlX2VxdWFsX29yX292ZXIuMTQiXSwiZmlsdGVyIjp7fSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsibmFtZSI6IkFnZSBFcXVh
            bCBvciBvdmVyIDE2IiwicGF0aCI6WyIkLmFnZV9lcXVhbF9vcl9vdmVyLjE2Il0sImZpbHRlciI6e30sImludGVudF90b19yZXRhaW4iOmZh
            bHNlfSx7Im5hbWUiOiJBZ2UgRXF1YWwgb3Igb3ZlciAxOCIsInBhdGgiOlsiJC5hZ2VfZXF1YWxfb3Jfb3Zlci4xOCJdLCJmaWx0ZXIiOnt9
            LCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJuYW1lIjoiQWdlIEVxdWFsIG9yIG92ZXIgMjEiLCJwYXRoIjpbIiQuYWdlX2VxdWFsX29y
            X292ZXIuMjEiXSwiZmlsdGVyIjp7fSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9XX19XX0sImNsaWVudF9tZXRhZGF0YSI6eyJqd2tzIjp7
            ImtleXMiOlt7Imt0eSI6IkVDIiwieCI6ImtaSUJzOHVobC1uUFFmZkd4a1FfR0diajhPcm03dnJqekcwSUl6aEkxbXciLCJ5Ijoib2ZsdjFs
            aWVFYmhpSXRmOG5qWmU1aDlDaGRWMFc4c2tPN1JMS1UtQjNZWSIsImNydiI6IlAtMjU2Iiwia2lkIjoiMTc4Njk2MjM5NzRhMWFmMiIsInVz
            ZSI6ImVuYyJ9XX0sImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZyI6IkVDREgtRVMiLCJhdXRob3JpemF0aW9uX2VuY3J5
            cHRlZF9yZXNwb25zZV9lbmMiOiJBMjU2R0NNIiwidnBfZm9ybWF0cyI6eyJ2YytzZC1qd3QiOnsic2Qtand0X2FsZ192YWx1ZXMiOlsiRVMy
            NTYiXSwia2Itand0X2FsZ192YWx1ZXMiOlsiRVMyNTYiXX19fSwiaWF0IjoxNzM2NzU0NTgyfQ.
            d53_mos8kemadVuxn-kNY5uCOIVlyg2_bbCD-c0cRpY1Mnax9CK-Fq8bNCeQ8MhjTCWBbuqo6Ql83k2mCrr9LYOT1gNjvc5YiHDNCmkqN9KZ
            2ZU7cmhJ6gRHOaQxYGx6vqEElQsyJulLtp_odiDcmywk8VC9ra5WTztEZycyH5Bjv6gPQ1-GXxl6A9_0aUMnxiCdUCTu9a7J9hXfM8WbblJa
            DZ00OUisOli-I5lDlmfSASgc10jPdlsmKDNa1ZW1dVezHDukUCAH5EPUsdC7HHXj_fDTkgICvVbBykq6-zWLda7kC0LvyXiQzuEeIFEzlP9u
            m0LQZeO-00GBYNI0PQ
        """.trimIndent().replace("\n", "")

    val authnRequest = JwsSigned.deserialize(JsonObject.serializer(), jws).getOrThrow().payload

    val authnRequestSerialized = vckJsonSerializer.encodeToString(authnRequest)

    withFixtureGenerator {
        RequestParser()
    } - {

        "request in URL parameters" { requestParser ->
            val input = URLBuilder("https://example.com").apply {
                authnRequest.encodeToParameters().forEach {
                    parameters.append(it.key, it.value)
                }
            }.buildString()

            requestParser.parseRequestParameters(input).getOrThrow().apply {
                shouldBeInstanceOf<RequestParametersFrom<AuthenticationRequestParameters>>()
                shouldBeInstanceOf<RequestParametersFrom.Uri<*>>()
                this.url.toString() shouldBe input
                parameters.assertParams()

                vckJsonSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(
                    vckJsonSerializer.encodeToString<RequestParametersFrom<AuthenticationRequestParameters>>(this)
                ).shouldBe(this)
            }
        }

        "plain request directly" { requestParser ->
            requestParser.parseRequestParameters(authnRequestSerialized).getOrThrow().apply {
                shouldBeInstanceOf<RequestParametersFrom<AuthenticationRequestParameters>>()
                shouldBeInstanceOf<RequestParametersFrom.Json<*>>()
                jsonString shouldBe authnRequestSerialized
                parameters.assertParams()

                vckJsonSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(
                    vckJsonSerializer.encodeToString<RequestParametersFrom<AuthenticationRequestParameters>>(this)
                ).shouldBe(this)
            }
        }

        "signed request directly" { requestParser ->
            requestParser.parseRequestParameters(jws).getOrThrow().apply {
                shouldBeInstanceOf<RequestParametersFrom<AuthenticationRequestParameters>>()
                shouldBeInstanceOf<RequestParametersFrom.JwsSigned<*>>()
                jwsSigned.serialize() shouldBe jws
                parameters.assertParams()

                vckJsonSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(
                    vckJsonSerializer.encodeToString<RequestParametersFrom<AuthenticationRequestParameters>>(this)
                ).shouldBe(this)
            }
        }


        "signed request by value" { requestParser ->
            val input = "https://example.com?request=$jws"

            requestParser.parseRequestParameters(input).getOrThrow().apply {
                shouldBeInstanceOf<RequestParametersFrom<AuthenticationRequestParameters>>()
                shouldBeInstanceOf<RequestParametersFrom.JwsSigned<*>>()
                jwsSigned.serialize() shouldBe jws
                parent.toString() shouldBe input
                parameters.assertParams()

                vckJsonSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(
                    vckJsonSerializer.encodeToString<RequestParametersFrom<AuthenticationRequestParameters>>(this)
                ).shouldBe(this)
            }
        }

        "signed request from DCAPI" { requestParser ->
            val input = DCAPIWalletRequest.OpenId4VpSigned(
                request = JarRequestParameters(request = jws),
                credentialId = "1",
                callingPackageName = "com.example.app",
                callingOrigin = "https://example.com"
            )

            requestParser.parseRequestParameters(input).getOrThrow().apply {
                shouldBeInstanceOf<RequestParametersFrom<AuthenticationRequestParameters>>()
                shouldBeInstanceOf<RequestParametersFrom.DcApiSigned<*>>()
                jwsSigned.serialize() shouldBe jws
                parameters.assertParams()

                vckJsonSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(
                    vckJsonSerializer.encodeToString<RequestParametersFrom<AuthenticationRequestParameters>>(this)
                ).shouldBe(this)
            }
        }

        "unsigned request from DCAPI" { requestParser ->
            val input = DCAPIWalletRequest.OpenId4VpUnsigned(
                    request = vckJsonSerializer.decodeFromString(authnRequestSerialized),
                    credentialId = "1",
                    callingPackageName = "com.example.app",
                    callingOrigin = "https://example.com"
                )

            requestParser.parseRequestParameters(input).getOrThrow().apply {
                shouldBeInstanceOf<RequestParametersFrom<AuthenticationRequestParameters>>()
                shouldBeInstanceOf<RequestParametersFrom.DcApiUnsigned<*>>()
                //jsonString shouldBe authnRequestSerialized // TODO Don't know why this is not the same
                parameters.assertParams()

                vckJsonSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(
                    vckJsonSerializer.encodeToString<RequestParametersFrom<AuthenticationRequestParameters>>(this)
                ).shouldBe(this)
            }
        }
    }

    withFixtureGenerator {
        RequestParser(
            remoteResourceRetriever = {
                if (it.url == "https://client.example.org/req/1234567890") authnRequestSerialized else null
            }
        )
    } - {

        "plain request by reference" { requestParser ->
            val input = "https://example.com?request_uri=https%3A%2F%2Fclient.example.org%2Freq%2F1234567890"

            requestParser.parseRequestParameters(input).getOrThrow().apply {
                shouldBeInstanceOf<RequestParametersFrom<AuthenticationRequestParameters>>()
                shouldBeInstanceOf<RequestParametersFrom.Json<*>>()
                jsonString shouldBe authnRequestSerialized
                parent.toString() shouldBe input
                parameters.assertParams()

                vckJsonSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(
                    vckJsonSerializer.encodeToString<RequestParametersFrom<AuthenticationRequestParameters>>(this)
                ).shouldBe(this)
            }
        }

    }
    withFixtureGenerator {
        RequestParser(
            remoteResourceRetriever = {
                if (it.url == "https://client.example.org/req/1234567890") jws else null
            }
        )
    } - {
        "signed request by reference" { requestParser ->
            val input = "https://example.com?request_uri=https%3A%2F%2Fclient.example.org%2Freq%2F1234567890"

            requestParser.parseRequestParameters(input).getOrThrow().apply {
                shouldBeInstanceOf<RequestParametersFrom<AuthenticationRequestParameters>>()
                shouldBeInstanceOf<RequestParametersFrom.JwsSigned<*>>()
                jwsSigned.serialize() shouldBe jws
                parent.toString() shouldBe input
                parameters.assertParams()

                vckJsonSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(
                    vckJsonSerializer.encodeToString<RequestParametersFrom<AuthenticationRequestParameters>>(this)
                ).shouldBe(this)
            }
        }

    }
}

private fun AuthenticationRequestParameters.assertParams() {
    responseUrl shouldBe "https://verifier.funke.wwwallet.org/verification/direct_post"
    clientId shouldBe "verifier.funke.wwwallet.org"
    clientIdWithoutPrefix shouldBe "verifier.funke.wwwallet.org"
    presentationDefinition.shouldNotBeNull()
        .inputDescriptors.first()
        .constraints.shouldNotBeNull()
        .fields.shouldNotBeNull().apply {
            this shouldHaveSize 20
            first { it.path == listOf("$.vct") }
                .filter.shouldNotBeNull()
                .enum.shouldNotBeNull() shouldContain "urn:eu.europa.ec.eudi:pid:1"
        }

}
package at.asitplus.wallet.lib.oidc

import at.asitplus.crypto.datatypes.jws.JweAlgorithm
import at.asitplus.crypto.datatypes.jws.JwsAlgorithm
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.oidvci.decodeFromPostBody
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSingleElement
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.Instant

/**
 * Tests our SIOP implementation against EUDI Ref Impl.,
 * see [https://verifier.eudiw.dev/cbor-selectable/verifiable](https://verifier.eudiw.dev/cbor-selectable/verifiable)
 */
class OidcSiopInteropTest : FreeSpec({

    lateinit var holderCryptoService: CryptoService
    lateinit var holderAgent: Holder
    lateinit var holderSiop: OidcSiopWallet

    beforeSpec {
        at.asitplus.wallet.eupid.Initializer.initWithVcLib()
    }

    beforeEach {
        holderCryptoService = DefaultCryptoService()
        holderAgent = HolderAgent.newDefaultInstance(holderCryptoService)
        runBlocking {
            holderAgent.storeCredentials(
                IssuerAgent.newDefaultInstance(
                    DefaultCryptoService(),
                    dataProvider = DummyCredentialDataProvider(),
                ).issueCredential(
                    subjectPublicKey = holderCryptoService.publicKey,
                    attributeTypes = listOf(EuPidScheme.vcType),
                    representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    claimNames = EuPidScheme.claimNames
                ).toStoreCredentialInput()
            )
        }
    }

    "EUDI from URL 2024-05-08" {
        val url = """
            eudi-openid4vp://verifier-backend.eudiw.dev?client_id=verifier-backend.eudiw.dev&request
            _uri=https%3A%2F%2Fverifier-backend.eudiw.dev%2Fwallet%2Frequest.jwt%2Flif-P02Wm25thTKoc
            ReEjQar-KqmmAYMo7xW_nNqTmum6yq0l_1qqLIxn2BYVwKDPU_dd0BGZjN1Cga4kVO_nw
        """.trimIndent().replace("\n", "")

        val requestObject = """
        eyJ4NWMiOlsiTUlJREtqQ0NBckNnQXdJQkFnSVVmeTl1NlNMdGdOdWY5UFhZYmgvUURxdVh6NTB3Q2dZSUtvWkl6ajBF
        QXdJd1hERWVNQndHQTFVRUF3d1ZVRWxFSUVsemMzVmxjaUJEUVNBdElGVlVJREF4TVMwd0t3WURWUVFLRENSRlZVUkpJ
        RmRoYkd4bGRDQlNaV1psY21WdVkyVWdTVzF3YkdWdFpXNTBZWFJwYjI0eEN6QUpCZ05WQkFZVEFsVlVNQjRYRFRJME1E
        SXlOakF5TXpZek0xb1hEVEkyTURJeU5UQXlNell6TWxvd2FURWRNQnNHQTFVRUF3d1VSVlZFU1NCU1pXMXZkR1VnVm1W
        eWFXWnBaWEl4RERBS0JnTlZCQVVUQXpBd01URXRNQ3NHQTFVRUNnd2tSVlZFU1NCWFlXeHNaWFFnVW1WbVpYSmxibU5s
        SUVsdGNHeGxiV1Z1ZEdGMGFXOXVNUXN3Q1FZRFZRUUdFd0pWVkRCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhB
        MElBQk1iV0JBQzFHaitHRE8veUNTYmdiRndwaXZQWVdMekV2SUxOdGRDdjdUeDFFc3hQQ3hCcDNEWkI0RklyNEJsbVZZ
        dEdhVWJvVklpaFJCaVFEbzNNcFdpamdnRkJNSUlCUFRBTUJnTlZIUk1CQWY4RUFqQUFNQjhHQTFVZEl3UVlNQmFBRkxO
        c3VKRVhITmVrR21ZeGgwTGhpOEJBekpVYk1DVUdBMVVkRVFRZU1CeUNHblpsY21sbWFXVnlMV0poWTJ0bGJtUXVaWFZr
        YVhjdVpHVjJNQklHQTFVZEpRUUxNQWtHQnlpQmpGMEZBUVl3UXdZRFZSMGZCRHd3T2pBNG9EYWdOSVl5YUhSMGNITTZM
        eTl3Y21Wd2NtOWtMbkJyYVM1bGRXUnBkeTVrWlhZdlkzSnNMM0JwWkY5RFFWOVZWRjh3TVM1amNtd3dIUVlEVlIwT0JC
        WUVGRmdtQWd1QlN2U25tNjhaem81SVN0SXYyZk0yTUE0R0ExVWREd0VCL3dRRUF3SUhnREJkQmdOVkhSSUVWakJVaGxK
        b2RIUndjem92TDJkcGRHaDFZaTVqYjIwdlpYVXRaR2xuYVhSaGJDMXBaR1Z1ZEdsMGVTMTNZV3hzWlhRdllYSmphR2ww
        WldOMGRYSmxMV0Z1WkMxeVpXWmxjbVZ1WTJVdFpuSmhiV1YzYjNKck1Bb0dDQ3FHU000OUJBTUNBMmdBTUdVQ01RREdm
        Z0xLbmJLaGlPVkYzeFNVMGFlanUvbmVHUVVWdU5ic1F3MExlRER3SVcrckxhdGViUmdvOWhNWERjM3dybFVDTUFJWnlK
        N2xSUlZleU1yM3dqcWtCRjJsOVliMHdPUXBzblpCQVZVQVB5STV4aFdYMlNBYXpvbTJKanNOL2FLQWtRPT0iLCJNSUlE
        SFRDQ0FxT2dBd0lCQWdJVVZxamd0SnFmNGhVWUprcWRZemkrMHh3aHdGWXdDZ1lJS29aSXpqMEVBd013WERFZU1Cd0dB
        MVVFQXd3VlVFbEVJRWx6YzNWbGNpQkRRU0F0SUZWVUlEQXhNUzB3S3dZRFZRUUtEQ1JGVlVSSklGZGhiR3hsZENCU1pX
        WmxjbVZ1WTJVZ1NXMXdiR1Z0Wlc1MFlYUnBiMjR4Q3pBSkJnTlZCQVlUQWxWVU1CNFhEVEl6TURrd01URTRNelF4TjFv
        WERUTXlNVEV5TnpFNE16UXhObG93WERFZU1Cd0dBMVVFQXd3VlVFbEVJRWx6YzNWbGNpQkRRU0F0SUZWVUlEQXhNUzB3
        S3dZRFZRUUtEQ1JGVlVSSklGZGhiR3hsZENCU1pXWmxjbVZ1WTJVZ1NXMXdiR1Z0Wlc1MFlYUnBiMjR4Q3pBSkJnTlZC
        QVlUQWxWVU1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFRmc1U2hmc3hwNVIvVUZJRUtTM0wyN2R3bkZobmpT
        Z1VoMmJ0S09RRW5mYjNkb3llcU1BdkJ0VU1sQ2xoc0YzdWVmS2luQ3cwOE5CMzFyd0MrZHRqNlgvTEUzbjJDOWpST0lV
        TjhQcm5sTFM1UXM0UnM0WlU1T0lnenRvYU84RzlvNElCSkRDQ0FTQXdFZ1lEVlIwVEFRSC9CQWd3QmdFQi93SUJBREFm
        QmdOVkhTTUVHREFXZ0JTemJMaVJGeHpYcEJwbU1ZZEM0WXZBUU15Vkd6QVdCZ05WSFNVQkFmOEVEREFLQmdncmdRSUNB
        QUFCQnpCREJnTlZIUjhFUERBNk1EaWdOcUEwaGpKb2RIUndjem92TDNCeVpYQnliMlF1Y0d0cExtVjFaR2wzTG1SbGRp
        OWpjbXd2Y0dsa1gwTkJYMVZVWHpBeExtTnliREFkQmdOVkhRNEVGZ1FVczJ5NGtSY2MxNlFhWmpHSFF1R0x3RURNbFJz
        d0RnWURWUjBQQVFIL0JBUURBZ0VHTUYwR0ExVWRFZ1JXTUZTR1VtaDBkSEJ6T2k4dloybDBhSFZpTG1OdmJTOWxkUzFr
        YVdkcGRHRnNMV2xrWlc1MGFYUjVMWGRoYkd4bGRDOWhjbU5vYVhSbFkzUjFjbVV0WVc1a0xYSmxabVZ5Wlc1alpTMW1j
        bUZ0WlhkdmNtc3dDZ1lJS29aSXpqMEVBd01EYUFBd1pRSXdhWFVBM2orK3hsL3RkRDc2dFhFV0Npa2ZNMUNhUno0dnpC
        QzdOUzB3Q2RJdEtpejZIWmVWOEVQdE5DbnNmS3BOQWpFQXFyZGVLRG5yNUt3ZjhCQTd0QVRlaHhObE9WNEhuYzEwWE8x
        WFVMdGlnQ3diNDlScGtxbFMySHVsK0RwcU9iVXMiXSwidHlwIjoib2F1dGgtYXV0aHotcmVxK2p3dCIsImFsZyI6IkVT
        MjU2In0.eyJyZXNwb25zZV91cmkiOiJodHRwczovL3ZlcmlmaWVyLWJhY2tlbmQuZXVkaXcuZGV2L3dhbGxldC9kaXJl
        Y3RfcG9zdCIsImNsaWVudF9pZF9zY2hlbWUiOiJ4NTA5X3Nhbl9kbnMiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4i
        LCJub25jZSI6Ijg3MTRjMWIyLTRlYzQtNDFlMS04YmJmLTBiZDRjYjZiM2Q3YSIsImNsaWVudF9pZCI6InZlcmlmaWVy
        LWJhY2tlbmQuZXVkaXcuZGV2IiwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0Lmp3dCIsImF1ZCI6Imh0dHBzOi8v
        c2VsZi1pc3N1ZWQubWUvdjIiLCJzY29wZSI6IiIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiMzJmNTQx
        NjMtNzE2Ni00OGYxLTkzZDgtZmYyMTdiZGIwNjUzIiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiZXUuZXVyb3Bh
        LmVjLmV1ZGl3LnBpZC4xIiwibmFtZSI6IkVVREkgUElEIiwicHVycG9zZSI6IldlIG5lZWQgdG8gdmVyaWZ5IHlvdXIg
        aWRlbnRpdHkiLCJmb3JtYXQiOnsibXNvX21kb2MiOnsiYWxnIjpbIkVTMjU2IiwiRVMzODQiLCJFUzUxMiIsIkVkRFNB
        IiwiRVNCMjU2IiwiRVNCMzIwIiwiRVNCMzg0IiwiRVNCNTEyIl19fSwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJw
        YXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQuMSddWydmYW1pbHlfbmFtZSddIl0sImludGVudF90b19yZXRh
        aW4iOmZhbHNlfSx7InBhdGgiOlsiJFsnZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xJ11bJ2JpcnRoX2RhdGUnXSJdLCJp
        bnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQuMSddWydnaXZl
        bl9uYW1lJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9XX19XX0sInN0YXRlIjoibGlmLVAwMldtMjV0aFRLb2NS
        ZUVqUWFyLUtxbW1BWU1vN3hXX25OcVRtdW02eXEwbF8xcXFMSXhuMkJZVndLRFBVX2RkMEJHWmpOMUNnYTRrVk9fbnci
        LCJpYXQiOjE3MTUxNTAwNzMsImNsaWVudF9tZXRhZGF0YSI6eyJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25z
        ZV9hbGciOiJFQ0RILUVTIiwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jIjoiQTEyOENCQy1IUzI1
        NiIsImlkX3Rva2VuX2VuY3J5cHRlZF9yZXNwb25zZV9hbGciOiJSU0EtT0FFUC0yNTYiLCJpZF90b2tlbl9lbmNyeXB0
        ZWRfcmVzcG9uc2VfZW5jIjoiQTEyOENCQy1IUzI1NiIsImp3a3NfdXJpIjoiaHR0cHM6Ly92ZXJpZmllci1iYWNrZW5k
        LmV1ZGl3LmRldi93YWxsZXQvamFybS9saWYtUDAyV20yNXRoVEtvY1JlRWpRYXItS3FtbUFZTW83eFdfbk5xVG11bTZ5
        cTBsXzFxcUxJeG4yQllWd0tEUFVfZGQwQkdaak4xQ2dhNGtWT19udy9qd2tzLmpzb24iLCJzdWJqZWN0X3N5bnRheF90
        eXBlc19zdXBwb3J0ZWQiOlsidXJuOmlldGY6cGFyYW1zOm9hdXRoOmp3ay10aHVtYnByaW50Il0sImlkX3Rva2VuX3Np
        Z25lZF9yZXNwb25zZV9hbGciOiJSUzI1NiJ9fQ.-qNymEtka8jQvM3F2Rjl551kHrvnZTknfy3gD4K9o3QUKWlYQzeie
        mBMp1YvSfOzMf-U-sryEJV8T9ANWiQNAw
        """.trimIndent()

        val jwkset = """
            {
                "keys": [
                    {
                        "kty": "EC",
                        "use": "enc",
                        "crv": "P-256",
                        "kid": "0e30be2d-1e8f-482d-b345-26f9f06b4243",
                        "x": "xFWlKn9MeGVkvtQgbVIqC0Qc6499LN9eEGixzYsJ3tg",
                        "y": "IcS_SK-kAeb4xaDM8qMlunPf5_LjSgkZ_xPj4kutVKs",
                        "alg": "ECDH-ES"
                    }
                ]
            }
        """.trimIndent()

        holderSiop = OidcSiopWallet.newDefaultInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService,
            remoteResourceRetriever = {
                if (it == "https://verifier-backend.eudiw.dev/wallet/jarm/" +
                    "lif-P02Wm25thTKocReEjQar-KqmmAYMo7xW_nNqTmum6yq0l_1qqLIxn2BYVwKDPU_dd0BGZjN1Cga4kVO_nw/jwks.json"
                ) jwkset else if (it == "https://verifier-backend.eudiw.dev/wallet/request.jwt/" +
                    "lif-P02Wm25thTKocReEjQar-KqmmAYMo7xW_nNqTmum6yq0l_1qqLIxn2BYVwKDPU_dd0BGZjN1Cga4kVO_nw"
                ) requestObject else null
            }
        )

        val resp = holderSiop.retrieveAuthenticationRequestParameters(url)
        Napier.d("resp: $resp")

        val response = holderSiop.createAuthnResponse(url).getOrThrow()

        response.shouldBeInstanceOf<AuthenticationResponseResult.Post>()
        val jarmParams = response.params.formUrlEncode().decodeFromPostBody<AuthenticationResponseParameters>()
        val jarm = jarmParams.response
        jarm.shouldNotBeNull()
        val params = AuthenticationResponseParameters.deserialize(JwsSigned.parse(jarm)!!.payload.decodeToString())
            .getOrThrow().shouldNotBeNull()

        params.presentationSubmission.shouldNotBeNull()
        params.vpToken.shouldNotBeNull()
        params.idToken.shouldNotBeNull()
    }

    "EUDI AuthnRequest can be parsed" {
        val input = """
            {
            "response_uri": "https://verifier-backend.eudiw.dev/wallet/direct_post",
            "client_id_scheme": "x509_san_dns",
            "response_type": "vp_token",
            "nonce": "nonce",
            "client_id": "verifier-backend.eudiw.dev",
            "response_mode": "direct_post.jwt",
            "aud": "https://self-issued.me/v2",
            "scope": "",
            "presentation_definition": {
                "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
                "input_descriptors": [
                    {
                        "id": "eudi_pid",
                        "name": "EUDI PID",
                        "purpose": "We need to verify your identity",
                        "constraints": {
                            "fields": [
                                {
                                    "path": [
                                        "${'$'}.mdoc.doctype"
                                    ],
                                    "filter": {
                                        "type": "string",
                                        "const": "eu.europa.ec.eudiw.pid.1"
                                    }
                                },
                                {
                                    "path": [
                                        "${'$'}.mdoc.namespace"
                                    ],
                                    "filter": {
                                        "type": "string",
                                        "const": "eu.europa.ec.eudiw.pid.1"
                                    }
                                },
                                {
                                    "path": [
                                        "${'$'}.mdoc.given_name"
                                    ],
                                    "intent_to_retain": false
                                }
                            ]
                        }
                    }
                ]
            },
            "state": "xgagB1vsIrWhMLixoJTCVZZvOHsZ8QrulEFxc0bjJdMRyzqO6j2-UB00gmOZraocfoknlxXY-kaoLlX8kygqxw",
            "iat": 1710313534,
            "client_metadata": {
                "authorization_encrypted_response_alg": "ECDH-ES",
                "authorization_encrypted_response_enc": "A128CBC-HS256",
                "id_token_encrypted_response_alg": "RSA-OAEP-256",
                "id_token_encrypted_response_enc": "A128CBC-HS256",
                "jwks_uri": "https://verifier-backend.eudiw.dev/wallet/jarm/xgagB1vsIrWhMLixoJTCVZZvOHsZ8QrulEFxc0bjJdMRyzqO6j2-UB00gmOZraocfoknlxXY-kaoLlX8kygqxw/jwks.json",
                "subject_syntax_types_supported": [
                    "urn:ietf:params:oauth:jwk-thumbprint"
                ],
                "id_token_signed_response_alg": "RS256"
            }
        }
        """.trimIndent()

        val parsed = jsonSerializer.decodeFromString<AuthenticationRequestParameters>(input)
        parsed.shouldNotBeNull()

        parsed.responseUrl shouldBe "https://verifier-backend.eudiw.dev/wallet/direct_post"
        parsed.clientIdScheme shouldBe "x509_san_dns"
        parsed.responseType shouldBe "vp_token"
        parsed.nonce shouldBe "nonce"
        parsed.clientId shouldBe "verifier-backend.eudiw.dev"
        parsed.responseMode shouldBe "direct_post.jwt"
        parsed.audience shouldBe "https://self-issued.me/v2"
        parsed.scope shouldBe ""
        val pd = parsed.presentationDefinition
        pd.shouldNotBeNull()
        pd.id shouldBe "32f54163-7166-48f1-93d8-ff217bdb0653"
        val id = pd.inputDescriptors.firstOrNull()
        id.shouldNotBeNull()
        id.id shouldBe "eudi_pid"
        id.name shouldBe "EUDI PID"
        id.purpose shouldBe "We need to verify your identity"
        val fields = id.constraints?.fields
        fields.shouldNotBeNull()
        fields.filter { it.path.contains("$.mdoc.doctype") }.shouldBeSingleton()
        fields.filter { it.path.contains("$.mdoc.namespace") }.shouldBeSingleton()
        fields.filter { it.path.contains("$.mdoc.given_name") }.shouldBeSingleton()
        parsed.state shouldBe "xgagB1vsIrWhMLixoJTCVZZvOHsZ8QrulEFxc0bjJdMRyzqO6j2-UB00gmOZraocfoknlxXY-kaoLlX8kygqxw"
        parsed.issuedAt shouldBe Instant.fromEpochSeconds(1710313534)
        val cm = parsed.clientMetadata
        cm.shouldNotBeNull()
        cm.subjectSyntaxTypesSupported.shouldNotBeNull() shouldHaveSingleElement "urn:ietf:params:oauth:jwk-thumbprint"
        cm.authorizationEncryptedResponseAlg shouldBe JweAlgorithm.ECDH_ES
        cm.authorizationEncryptedResponseEncoding shouldBe "A128CBC-HS256"
        cm.idTokenEncryptedResponseAlg shouldBe JweAlgorithm.RSA_OAEP_256
        cm.idTokenEncryptedResponseEncoding shouldBe "A128CBC-HS256"
        cm.idTokenSignedResponseAlg shouldBe JwsAlgorithm.RS256
        cm.jsonWebKeySetUrl shouldBe "https://verifier-backend.eudiw.dev/wallet/jarm/" +
                "xgagB1vsIrWhMLixoJTCVZZvOHsZ8QrulEFxc0bjJdMRyzqO6j2-UB00gmOZraocfoknlxXY-kaoLlX8kygqxw/jwks.json"
    }

    "Request in request URI" {
        val input = "mdoc-openid4vp://?request_uri=https%3A%2F%2Fexample.com%2Fd15b5b6f-7821-4031-9a18-ebe491b720a6"
        val jws = DefaultJwsService(DefaultCryptoService()).createSignedJwsAddingParams(
            payload = AuthenticationRequestParameters(
                nonce = "RjEQKQeG8OUaKT4ij84E8mCvry6pVSgDyqRBMW5eBTPItP4DIfbKaT6M6v6q2Dvv8fN7Im7Ifa6GI2j6dHsJaQ==",
                state = "ef391e30-bacc-4441-af5d-7f42fb682e02",
                responseUrl = "https://example.com/ef391e30-bacc-4441-af5d-7f42fb682e02",
                clientId = "https://example.com/ef391e30-bacc-4441-af5d-7f42fb682e02",
            ).serialize().encodeToByteArray()
        ).getOrThrow().serialize()

        val wallet = OidcSiopWallet.newDefaultInstance(
            remoteResourceRetriever = { url ->
                if (url == "https://example.com/d15b5b6f-7821-4031-9a18-ebe491b720a6") jws else null
            }
        )

        val parsed = wallet.parseAuthenticationRequestParameters(input).getOrThrow()

        parsed.nonce shouldBe "RjEQKQeG8OUaKT4ij84E8mCvry6pVSgDyqRBMW5eBTPItP4DIfbKaT6M6v6q2Dvv8fN7Im7Ifa6GI2j6dHsJaQ=="
        parsed.state shouldBe "ef391e30-bacc-4441-af5d-7f42fb682e02"
        parsed.responseUrl shouldBe "https://example.com/ef391e30-bacc-4441-af5d-7f42fb682e02"
        parsed.clientId shouldBe parsed.responseUrl
    }

    "empty client_id" {
        val input = "mdoc-openid4vp://?response_type=vp_token&client_id=&response_mode=direct_post.jwt"

        Url(input).parameters.flattenEntries().toMap()
            .decodeFromUrlQuery<AuthenticationRequestParameters>().shouldNotBeNull()
    }

})



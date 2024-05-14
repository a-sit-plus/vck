package at.asitplus.wallet.lib.oidc

import at.asitplus.crypto.datatypes.jws.JweAlgorithm
import at.asitplus.crypto.datatypes.jws.JwsAlgorithm
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.*
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
import io.ktor.http.Url
import io.ktor.util.flattenEntries
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
            eyJ4NWMiOlsiTUlJREtqQ0NBckNnQXdJQkFnSVVmeTl1NlNMdGdOdWY5UFhZYmgvUURxdVh6NTB3Q2dZSUtvWkl6ajBFQXdJd1hERWVNQndHQTFVRUF3d1ZV
            RWxFSUVsemMzVmxjaUJEUVNBdElGVlVJREF4TVMwd0t3WURWUVFLRENSRlZVUkpJRmRoYkd4bGRDQlNaV1psY21WdVkyVWdTVzF3YkdWdFpXNTBZWFJwYjI0
            eEN6QUpCZ05WQkFZVEFsVlVNQjRYRFRJME1ESXlOakF5TXpZek0xb1hEVEkyTURJeU5UQXlNell6TWxvd2FURWRNQnNHQTFVRUF3d1VSVlZFU1NCU1pXMXZk
            R1VnVm1WeWFXWnBaWEl4RERBS0JnTlZCQVVUQXpBd01URXRNQ3NHQTFVRUNnd2tSVlZFU1NCWFlXeHNaWFFnVW1WbVpYSmxibU5sSUVsdGNHeGxiV1Z1ZEdG
            MGFXOXVNUXN3Q1FZRFZRUUdFd0pWVkRCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQk1iV0JBQzFHaitHRE8veUNTYmdiRndwaXZQWVdMekV2
            SUxOdGRDdjdUeDFFc3hQQ3hCcDNEWkI0RklyNEJsbVZZdEdhVWJvVklpaFJCaVFEbzNNcFdpamdnRkJNSUlCUFRBTUJnTlZIUk1CQWY4RUFqQUFNQjhHQTFV
            ZEl3UVlNQmFBRkxOc3VKRVhITmVrR21ZeGgwTGhpOEJBekpVYk1DVUdBMVVkRVFRZU1CeUNHblpsY21sbWFXVnlMV0poWTJ0bGJtUXVaWFZrYVhjdVpHVjJN
            QklHQTFVZEpRUUxNQWtHQnlpQmpGMEZBUVl3UXdZRFZSMGZCRHd3T2pBNG9EYWdOSVl5YUhSMGNITTZMeTl3Y21Wd2NtOWtMbkJyYVM1bGRXUnBkeTVrWlhZ
            dlkzSnNMM0JwWkY5RFFWOVZWRjh3TVM1amNtd3dIUVlEVlIwT0JCWUVGRmdtQWd1QlN2U25tNjhaem81SVN0SXYyZk0yTUE0R0ExVWREd0VCL3dRRUF3SUhn
            REJkQmdOVkhSSUVWakJVaGxKb2RIUndjem92TDJkcGRHaDFZaTVqYjIwdlpYVXRaR2xuYVhSaGJDMXBaR1Z1ZEdsMGVTMTNZV3hzWlhRdllYSmphR2wwWldO
            MGRYSmxMV0Z1WkMxeVpXWmxjbVZ1WTJVdFpuSmhiV1YzYjNKck1Bb0dDQ3FHU000OUJBTUNBMmdBTUdVQ01RREdmZ0xLbmJLaGlPVkYzeFNVMGFlanUvbmVH
            UVVWdU5ic1F3MExlRER3SVcrckxhdGViUmdvOWhNWERjM3dybFVDTUFJWnlKN2xSUlZleU1yM3dqcWtCRjJsOVliMHdPUXBzblpCQVZVQVB5STV4aFdYMlNB
            YXpvbTJKanNOL2FLQWtRPT0iLCJNSUlESFRDQ0FxT2dBd0lCQWdJVVZxamd0SnFmNGhVWUprcWRZemkrMHh3aHdGWXdDZ1lJS29aSXpqMEVBd013WERFZU1C
            d0dBMVVFQXd3VlVFbEVJRWx6YzNWbGNpQkRRU0F0SUZWVUlEQXhNUzB3S3dZRFZRUUtEQ1JGVlVSSklGZGhiR3hsZENCU1pXWmxjbVZ1WTJVZ1NXMXdiR1Z0
            Wlc1MFlYUnBiMjR4Q3pBSkJnTlZCQVlUQWxWVU1CNFhEVEl6TURrd01URTRNelF4TjFvWERUTXlNVEV5TnpFNE16UXhObG93WERFZU1Cd0dBMVVFQXd3VlVF
            bEVJRWx6YzNWbGNpQkRRU0F0SUZWVUlEQXhNUzB3S3dZRFZRUUtEQ1JGVlVSSklGZGhiR3hsZENCU1pXWmxjbVZ1WTJVZ1NXMXdiR1Z0Wlc1MFlYUnBiMjR4
            Q3pBSkJnTlZCQVlUQWxWVU1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFRmc1U2hmc3hwNVIvVUZJRUtTM0wyN2R3bkZobmpTZ1VoMmJ0S09RRW5m
            YjNkb3llcU1BdkJ0VU1sQ2xoc0YzdWVmS2luQ3cwOE5CMzFyd0MrZHRqNlgvTEUzbjJDOWpST0lVTjhQcm5sTFM1UXM0UnM0WlU1T0lnenRvYU84RzlvNElC
            SkRDQ0FTQXdFZ1lEVlIwVEFRSC9CQWd3QmdFQi93SUJBREFmQmdOVkhTTUVHREFXZ0JTemJMaVJGeHpYcEJwbU1ZZEM0WXZBUU15Vkd6QVdCZ05WSFNVQkFm
            OEVEREFLQmdncmdRSUNBQUFCQnpCREJnTlZIUjhFUERBNk1EaWdOcUEwaGpKb2RIUndjem92TDNCeVpYQnliMlF1Y0d0cExtVjFaR2wzTG1SbGRpOWpjbXd2
            Y0dsa1gwTkJYMVZVWHpBeExtTnliREFkQmdOVkhRNEVGZ1FVczJ5NGtSY2MxNlFhWmpHSFF1R0x3RURNbFJzd0RnWURWUjBQQVFIL0JBUURBZ0VHTUYwR0Ex
            VWRFZ1JXTUZTR1VtaDBkSEJ6T2k4dloybDBhSFZpTG1OdmJTOWxkUzFrYVdkcGRHRnNMV2xrWlc1MGFYUjVMWGRoYkd4bGRDOWhjbU5vYVhSbFkzUjFjbVV0
            WVc1a0xYSmxabVZ5Wlc1alpTMW1jbUZ0WlhkdmNtc3dDZ1lJS29aSXpqMEVBd01EYUFBd1pRSXdhWFVBM2orK3hsL3RkRDc2dFhFV0Npa2ZNMUNhUno0dnpC
            QzdOUzB3Q2RJdEtpejZIWmVWOEVQdE5DbnNmS3BOQWpFQXFyZGVLRG5yNUt3ZjhCQTd0QVRlaHhObE9WNEhuYzEwWE8xWFVMdGlnQ3diNDlScGtxbFMySHVs
            K0RwcU9iVXMiXSwidHlwIjoib2F1dGgtYXV0aHotcmVxK2p3dCIsImFsZyI6IkVTMjU2In0.eyJyZXNwb25zZV91cmkiOiJodHRwczovL3ZlcmlmaWVyLWJh
            Y2tlbmQuZXVkaXcuZGV2L3dhbGxldC9kaXJlY3RfcG9zdCIsImNsaWVudF9pZF9zY2hlbWUiOiJ4NTA5X3Nhbl9kbnMiLCJyZXNwb25zZV90eXBlIjoidnBf
            dG9rZW4iLCJub25jZSI6IjQyOTcwNDcwLTU1YzUtNDk1NS04YTY2LWNlMjgxMjU5YmJmYSIsImNsaWVudF9pZCI6InZlcmlmaWVyLWJhY2tlbmQuZXVkaXcu
            ZGV2IiwicmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0Lmp3dCIsImF1ZCI6Imh0dHBzOi8vc2VsZi1pc3N1ZWQubWUvdjIiLCJzY29wZSI6IiIsInByZXNl
            bnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiMzJmNTQxNjMtNzE2Ni00OGYxLTkzZDgtZmYyMTdiZGIwNjUzIiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7Imlk
            IjoiZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xIiwibmFtZSI6IkVVREkgUElEIiwicHVycG9zZSI6IldlIG5lZWQgdG8gdmVyaWZ5IHlvdXIgaWRlbnRpdHki
            LCJmb3JtYXQiOnsibXNvX21kb2MiOnsiYWxnIjpbIkVTMjU2IiwiRVMzODQiLCJFUzUxMiIsIkVkRFNBIiwiRVNCMjU2IiwiRVNCMzIwIiwiRVNCMzg0Iiwi
            RVNCNTEyIl19fSwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQuMSddWydmYW1pbHlfbmFtZSdd
            Il0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJFsnZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xJ11bJ2dpdmVuX25hbWUnXSJdLCJpbnRl
            bnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQuMSddWydiaXJ0aF9kYXRlJ10iXSwiaW50ZW50X3RvX3Jl
            dGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkWydldS5ldXJvcGEuZWMuZXVkaXcucGlkLjEnXVsnYWdlX292ZXJfMTgnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpm
            YWxzZX0seyJwYXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQuMSddWydhZ2VfaW5feWVhcnMnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0s
            eyJwYXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQuMSddWydhZ2VfYmlydGhfeWVhciddIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBh
            dGgiOlsiJFsnZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xJ11bJ2ZhbWlseV9uYW1lX2JpcnRoJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0
            aCI6WyIkWydldS5ldXJvcGEuZWMuZXVkaXcucGlkLjEnXVsnZ2l2ZW5fbmFtZV9iaXJ0aCddIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgi
            OlsiJFsnZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xJ11bJ2JpcnRoX3BsYWNlJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkWydl
            dS5ldXJvcGEuZWMuZXVkaXcucGlkLjEnXVsnYmlydGhfY291bnRyeSddIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJFsnZXUuZXVy
            b3BhLmVjLmV1ZGl3LnBpZC4xJ11bJ2JpcnRoX3N0YXRlJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkWydldS5ldXJvcGEuZWMu
            ZXVkaXcucGlkLjEnXVsnYmlydGhfY2l0eSddIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJFsnZXUuZXVyb3BhLmVjLmV1ZGl3LnBp
            ZC4xJ11bJ3Jlc2lkZW50X2FkZHJlc3MnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQu
            MSddWydyZXNpZGVudF9jb3VudHJ5J10iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkWydldS5ldXJvcGEuZWMuZXVkaXcucGlkLjEn
            XVsncmVzaWRlbnRfc3RhdGUnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQuMSddWydy
            ZXNpZGVudF9jaXR5J10iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkWydldS5ldXJvcGEuZWMuZXVkaXcucGlkLjEnXVsncmVzaWRl
            bnRfcG9zdGFsX2NvZGUnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQuMSddWydyZXNp
            ZGVudF9zdHJlZXQnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQuMSddWydyZXNpZGVu
            dF9ob3VzZV9udW1iZXInXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQuMSddWydnZW5k
            ZXInXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQuMSddWyduYXRpb25hbGl0eSddIl0s
            ImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJFsnZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xJ11bJ2lzc3VhbmNlX2RhdGUnXSJdLCJpbnRl
            bnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQuMSddWydleHBpcnlfZGF0ZSddIl0sImludGVudF90b19y
            ZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJFsnZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xJ11bJ2lzc3VpbmdfYXV0aG9yaXR5J10iXSwiaW50ZW50X3RvX3Jl
            dGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkWydldS5ldXJvcGEuZWMuZXVkaXcucGlkLjEnXVsnZG9jdW1lbnRfbnVtYmVyJ10iXSwiaW50ZW50X3RvX3JldGFp
            biI6ZmFsc2V9LHsicGF0aCI6WyIkWydldS5ldXJvcGEuZWMuZXVkaXcucGlkLjEnXVsnYWRtaW5pc3RyYXRpdmVfbnVtYmVyJ10iXSwiaW50ZW50X3RvX3Jl
            dGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkWydldS5ldXJvcGEuZWMuZXVkaXcucGlkLjEnXVsnaXNzdWluZ19jb3VudHJ5J10iXSwiaW50ZW50X3RvX3JldGFp
            biI6ZmFsc2V9LHsicGF0aCI6WyIkWydldS5ldXJvcGEuZWMuZXVkaXcucGlkLjEnXVsnaXNzdWluZ19qdXJpc2RpY3Rpb24nXSJdLCJpbnRlbnRfdG9fcmV0
            YWluIjpmYWxzZX1dfX1dfSwic3RhdGUiOiJHajdCQVRWTS1CYnZMQlZrajE0ckp3dkx3OHZSam9ObXFlZmI2WkR4VE5aRHVienV3S1BsTFF4c01FSUVuR1Vl
            S0RQXzAwT2E4dnQ0RWRfNXJ6TWxyZyIsImlhdCI6MTcxNTU4Mzk3OCwiY2xpZW50X21ldGFkYXRhIjp7ImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3Bv
            bnNlX2FsZyI6IkVDREgtRVMiLCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9lbmMiOiJBMTI4Q0JDLUhTMjU2IiwiaWRfdG9rZW5fZW5jcnlw
            dGVkX3Jlc3BvbnNlX2FsZyI6IlJTQS1PQUVQLTI1NiIsImlkX3Rva2VuX2VuY3J5cHRlZF9yZXNwb25zZV9lbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiandrc191
            cmkiOiJodHRwczovL3ZlcmlmaWVyLWJhY2tlbmQuZXVkaXcuZGV2L3dhbGxldC9qYXJtL0dqN0JBVFZNLUJidkxCVmtqMTRySnd2THc4dlJqb05tcWVmYjZa
            RHhUTlpEdWJ6dXdLUGxMUXhzTUVJRW5HVWVLRFBfMDBPYTh2dDRFZF81cnpNbHJnL2p3a3MuanNvbiIsInN1YmplY3Rfc3ludGF4X3R5cGVzX3N1cHBvcnRl
            ZCI6WyJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1icHJpbnQiXSwiaWRfdG9rZW5fc2lnbmVkX3Jlc3BvbnNlX2FsZyI6IlJTMjU2In19.ZaLTmqo
            262E_yHwCSDZQnAFvkVfmrYn9bzX0vXG6TSqEx7DkaONsCdl_IGF7aIDGXV-eV2ZSWm8aZAPWVyXscw
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

        val resp = holderSiop.parseAuthenticationRequestParameters(url)
        Napier.d("resp: $resp")

        val response = holderSiop.createAuthnResponse(url).getOrThrow()

        response.shouldBeInstanceOf<AuthenticationResponseResult.Post>()
        val jarmParams = response.params.formUrlEncode().decodeFromPostBody<AuthenticationResponseParameters>()
        val jarm = jarmParams.response
        jarm.shouldNotBeNull()
        val params =
            AuthenticationResponseParameters.deserialize(JwsSigned.parse(jarm).getOrThrow().payload.decodeToString())
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
            ).serialize().encodeToByteArray(),
            addX5c = false
        ).getOrThrow().serialize()

        val wallet = OidcSiopWallet.newDefaultInstance(
            remoteResourceRetriever = { url ->
                if (url == "https://example.com/d15b5b6f-7821-4031-9a18-ebe491b720a6") jws else null
            }
        )

        val parsed = wallet.parseAuthenticationRequestParameters(input).getOrThrow()

        parsed.parameters.nonce shouldBe "RjEQKQeG8OUaKT4ij84E8mCvry6pVSgDyqRBMW5eBTPItP4DIfbKaT6M6v6q2Dvv8fN7Im7Ifa6GI2j6dHsJaQ=="
        parsed.parameters.state shouldBe "ef391e30-bacc-4441-af5d-7f42fb682e02"
        parsed.parameters.responseUrl shouldBe "https://example.com/ef391e30-bacc-4441-af5d-7f42fb682e02"
        parsed.parameters.clientId shouldBe parsed.parameters.responseUrl
    }

    "empty client_id" {
        val input = "mdoc-openid4vp://?response_type=vp_token&client_id=&response_mode=direct_post.jwt"

        Url(input).parameters.flattenEntries().toMap()
            .decodeFromUrlQuery<AuthenticationRequestParameters>().shouldNotBeNull()
    }

})



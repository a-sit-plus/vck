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
import at.asitplus.wallet.lib.oidvci.decodeFromPostBody
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSingleElement
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
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
                ).toStoreCredentialInput()
            )
        }
    }

    "EUDI from URL" {
        val url = """
            eudi-openid4vp://verifier-backend.eudiw.dev?client_id=verifier-backend.eudiw.dev&request_uri=https%3A%2F%2F
            verifier-backend.eudiw.dev%2Fwallet%2Frequest.jwt%2FWLFJEn9AGbJfAcEyaQTzzxueqmeRazmsHIkxMRTkGRL1zyI7un
            -KJWaXtulrfiSS38LlU5ABDB9Zdsfq_11r8Q
        """.trimIndent().replace("\n", "")

        val requestObject = """
            eyJ4NWMiOlsiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVUkxha05EUVhKRFowRjNTVUpCWjBsVlpuazVkVFpU
            VEhSblRuVm1PVkJZV1dKb0wxRkVjWFZZZWpVd2QwTm5XVWxMYjFwSmVtb3dSVUYzU1hkWVJFVmxUVUozUjBFeFZVVkJkM2RXVlVWc1JVbEZi
            SHBqTTFac1kybENSRkZUUVhSSlJsWlZTVVJCZUUxVE1IZExkMWxFVmxGUlMwUkRVa1pXVlZKS1NVWmthR0pIZUd4a1EwSlRXbGRhYkdOdFZu
            VlpNbFZuVTFjeGQySkhWblJhVnpVd1dWaFNjR0l5TkhoRGVrRktRbWRPVmtKQldWUkJiRlpWVFVJMFdFUlVTVEJOUkVsNVRtcEJlVTE2V1hw
            Tk1XOVlSRlJKTWsxRVNYbE9WRUY1VFhwWmVrMXNiM2RoVkVWa1RVSnpSMEV4VlVWQmQzZFZVbFpXUlZOVFFsTmFWekYyWkVkVloxWnRWbmxo
            VjFwd1dsaEplRVJFUVV0Q1owNVdRa0ZWVkVGNlFYZE5WRVYwVFVOelIwRXhWVVZEWjNkclVsWldSVk5UUWxoWlYzaHpXbGhSWjFWdFZtMWFX
            RXBzWW0xT2JFbEZiSFJqUjNoc1lsZFdkV1JIUmpCaFZ6bDFUVkZ6ZDBOUldVUldVVkZIUlhkS1ZsWkVRbHBOUWsxSFFubHhSMU5OTkRsQlow
            VkhRME54UjFOTk5EbEJkMFZJUVRCSlFVSk5ZbGRDUVVNeFIyb3JSMFJQTDNsRFUySm5Za1ozY0dsMlVGbFhUSHBGZGtsTVRuUmtRM1kzVkhn
            eFJYTjRVRU40UW5BelJGcENORVpKY2pSQ2JHMVdXWFJIWVZWaWIxWkphV2hTUW1sUlJHOHpUWEJYYVdwblowWkNUVWxKUWxCVVFVMUNaMDVX
            U0ZKTlFrRm1PRVZCYWtGQlRVSTRSMEV4VldSSmQxRlpUVUpoUVVaTVRuTjFTa1ZZU0U1bGEwZHRXWGhvTUV4b2FUaENRWHBLVldKTlExVkhR
            VEZWWkVWUlVXVk5RbmxEUjI1YWJHTnRiRzFoVjFaNVRGZEthRmt5ZEd4aWJWRjFXbGhXYTJGWVkzVmFSMVl5VFVKSlIwRXhWV1JLVVZGTVRV
            RnJSMEo1YVVKcVJqQkdRVkZaZDFGM1dVUldVakJtUWtSM2QwOXFRVFJ2UkdGblRrbFplV0ZJVWpCalNFMDJUSGs1ZDJOdFZuZGpiVGxyVEc1
            Q2NtRlROV3hrVjFKd1pIazFhMXBZV1haWk0wcHpURE5DY0ZwR09VUlJWamxXVmtZNGQwMVROV3BqYlhkM1NGRlpSRlpTTUU5Q1FsbEZSa1pu
            YlVGbmRVSlRkbE51YlRZNFducHZOVWxUZEVsMk1tWk5NazFCTkVkQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQ1pFSm5UbFpJVWtsRlZtcENW
            V2hzU205a1NGSjNZM3B2ZGt3eVpIQmtSMmd4V1drMWFtSXlNSFphV0ZWMFdrZHNibUZZVW1oaVF6RndXa2RXZFdSSGJEQmxVekV6V1ZkNGMx
            cFlVWFpaV0VwcVlVZHNNRnBYVGpCa1dFcHNURmRHZFZwRE1YbGFWMXBzWTIxV2RWa3lWWFJhYmtwb1lsZFdNMkl6U25KTlFXOUhRME54UjFO
            Tk5EbENRVTFEUVRKblFVMUhWVU5OVVVSSFptZE1TMjVpUzJocFQxWkdNM2hUVlRCaFpXcDFMMjVsUjFGVlZuVk9Zbk5SZHpCTVpVUkVkMGxY
            SzNKTVlYUmxZbEpuYnpsb1RWaEVZek4zY214VlEwMUJTVnA1U2pkc1VsSldaWGxOY2pOM2FuRnJRa1l5YkRsWllqQjNUMUZ3YzI1YVFrRldW
            VUZRZVVrMWVHaFhXREpUUVdGNmIyMHlTbXB6VGk5aFMwRnJVVDA5Q2kwdExTMHRSVTVFSUVORlVsUkpSa2xEUVZSRkxTMHRMUzA9IiwiTFMw
            dExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVUklWRU5EUVhGUFowRjNTVUpCWjBsVlZuRnFaM1JLY1dZMGFGVlpTbXR4
            WkZsNmFTc3dlSGRvZDBaWmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhkWVJFVmxUVUozUjBFeFZVVkJkM2RXVlVWc1JVbEZiSHBqTTFac1kybENS
            RkZUUVhSSlJsWlZTVVJCZUUxVE1IZExkMWxFVmxGUlMwUkRVa1pXVlZKS1NVWmthR0pIZUd4a1EwSlRXbGRhYkdOdFZuVlpNbFZuVTFjeGQy
            SkhWblJhVnpVd1dWaFNjR0l5TkhoRGVrRktRbWRPVmtKQldWUkJiRlpWVFVJMFdFUlVTWHBOUkd0M1RWUkZORTE2VVhoT01XOVlSRlJOZVUx
            VVJYbE9la1UwVFhwUmVFNXNiM2RZUkVWbFRVSjNSMEV4VlVWQmQzZFdWVVZzUlVsRmJIcGpNMVpzWTJsQ1JGRlRRWFJKUmxaVlNVUkJlRTFU
            TUhkTGQxbEVWbEZSUzBSRFVrWldWVkpLU1Vaa2FHSkhlR3hrUTBKVFdsZGFiR050Vm5WWk1sVm5VMWN4ZDJKSFZuUmFWelV3V1ZoU2NHSXlO
            SGhEZWtGS1FtZE9Wa0pCV1ZSQmJGWlZUVWhaZDBWQldVaExiMXBKZW1vd1EwRlJXVVpMTkVWRlFVTkpSRmxuUVVWR1p6VlRhR1p6ZUhBMVVp
            OVZSa2xGUzFNelRESTNaSGR1Um1odWFsTm5WV2d5WW5STFQxRkZibVppTTJSdmVXVnhUVUYyUW5SVlRXeERiR2h6UmpOMVpXWkxhVzVEZHpB
            NFRrSXpNWEozUXl0a2RHbzJXQzlNUlROdU1rTTVhbEpQU1ZWT09GQnlibXhNVXpWUmN6UlNjelJhVlRWUFNXZDZkRzloVHpoSE9XODBTVUpL
            UkVORFFWTkJkMFZuV1VSV1VqQlVRVkZJTDBKQlozZENaMFZDTDNkSlFrRkVRV1pDWjA1V1NGTk5SVWRFUVZkblFsTjZZa3hwVWtaNGVsaHdR
            bkJ0VFZsa1F6Ulpka0ZSVFhsV1IzcEJWMEpuVGxaSVUxVkNRV1k0UlVSRVFVdENaMmR5WjFGSlEwRkJRVUpDZWtKRVFtZE9Wa2hTT0VWUVJF
            RTJUVVJwWjA1eFFUQm9ha3B2WkVoU2QyTjZiM1pNTTBKNVdsaENlV0l5VVhWalIzUndURzFXTVZwSGJETk1iVkpzWkdrNWFtTnRkM1pqUjJ4
            cldEQk9RbGd4VmxWWWVrRjRURzFPZVdKRVFXUkNaMDVXU0ZFMFJVWm5VVlZ6TW5rMGExSmpZekUyVVdGYWFrZElVWFZIVEhkRlJFMXNVbk4z
            UkdkWlJGWlNNRkJCVVVndlFrRlJSRUZuUlVkTlJqQkhRVEZWWkVWblVsZE5SbE5IVlcxb01HUklRbnBQYVRoMldqSnNNR0ZJVm1sTWJVNTJZ
            bE01YkdSVE1XdGhWMlJ3WkVkR2MweFhiR3RhVnpVd1lWaFNOVXhZWkdoaVIzaHNaRU01YUdOdFRtOWhXRkpzV1ROU01XTnRWWFJaVnpWclRG
            aEtiRnB0Vm5sYVZ6VnFXbE14YldOdFJuUmFXR1IyWTIxemQwTm5XVWxMYjFwSmVtb3dSVUYzVFVSaFFVRjNXbEZKZDJGWVZVRXphaXNyZUd3
            dmRHUkVOelowV0VWWFEybHJaazB4UTJGU2VqUjJla0pETjA1VE1IZERaRWwwUzJsNk5raGFaVlk0UlZCMFRrTnVjMlpMY0U1QmFrVkJjWEpr
            WlV0RWJuSTFTM2RtT0VKQk4zUkJWR1ZvZUU1c1QxWTBTRzVqTVRCWVR6RllWVXgwYVdkRGQySTBPVkp3YTNGc1V6SklkV3dyUkhCeFQySlZj
            d290TFMwdExVVk9SQ0JEUlZKVVNVWkpRMEZVUlMwdExTMHQiXSwidHlwIjoib2F1dGgtYXV0aHotcmVxK2p3dCIsImFsZyI6IkVTMjU2In0.
            eyJyZXNwb25zZV91cmkiOiJodHRwczovL3ZlcmlmaWVyLWJhY2tlbmQuZXVkaXcuZGV2L3dhbGxldC9kaXJlY3RfcG9zdCIsImNsaWVudF9p
            ZF9zY2hlbWUiOiJ4NTA5X3Nhbl9kbnMiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJub25jZSI6Im5vbmNlIiwiY2xpZW50X2lkIjoi
            dmVyaWZpZXItYmFja2VuZC5ldWRpdy5kZXYiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3Quand0IiwiYXVkIjoiaHR0cHM6Ly9zZWxm
            LWlzc3VlZC5tZS92MiIsInNjb3BlIjoiIiwicHJlc2VudGF0aW9uX2RlZmluaXRpb24iOnsiaWQiOiIzMmY1NDE2My03MTY2LTQ4ZjEtOTNk
            OC1mZjIxN2JkYjA2NTMiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiJldWRpX3BpZCIsIm5hbWUiOiJFVURJIFBJRCIsInB1cnBvc2Ui
            OiJXZSBuZWVkIHRvIHZlcmlmeSB5b3VyIGlkZW50aXR5IiwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQubWRvYy5kb2N0
            eXBlIl0sImZpbHRlciI6eyJ0eXBlIjoic3RyaW5nIiwiY29uc3QiOiJldS5ldXJvcGEuZWMuZXVkaXcucGlkLjEifX0seyJwYXRoIjpbIiQu
            bWRvYy5uYW1lc3BhY2UiXSwiZmlsdGVyIjp7InR5cGUiOiJzdHJpbmciLCJjb25zdCI6ImV1LmV1cm9wYS5lYy5ldWRpdy5waWQuMSJ9fSx7
            InBhdGgiOlsiJC5tZG9jLmZhbWlseV9uYW1lIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJC5tZG9jLmdpdmVuX25h
            bWUiXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm1kb2MuYmlydGhfZGF0ZSJdLCJpbnRlbnRfdG9fcmV0YWluIjpm
            YWxzZX0seyJwYXRoIjpbIiQubWRvYy5hZ2Vfb3Zlcl8xOCJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQubWRvYy5h
            Z2VfaW5feWVhcnMiXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm1kb2MuYWdlX2JpcnRoX3llYXIiXSwiaW50ZW50
            X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm1kb2MuZmFtaWx5X25hbWVfYmlydGgiXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9
            LHsicGF0aCI6WyIkLm1kb2MuZ2l2ZW5fbmFtZV9iaXJ0aCJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQubWRvYy5i
            aXJ0aF9wbGFjZSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQubWRvYy5iaXJ0aF9jb3VudHJ5Il0sImludGVudF90
            b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJC5tZG9jLmJpcnRoX3N0YXRlIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgi
            OlsiJC5tZG9jLmJpcnRoX2NpdHkiXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm1kb2MucmVzaWRlbnRfYWRkcmVz
            cyJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQubWRvYy5yZXNpZGVudF9jb3VudHJ5Il0sImludGVudF90b19yZXRh
            aW4iOmZhbHNlfSx7InBhdGgiOlsiJC5tZG9jLnJlc2lkZW50X3N0YXRlIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsi
            JC5tZG9jLnJlc2lkZW50X2NpdHkiXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm1kb2MucmVzaWRlbnRfcG9zdGFs
            X2NvZGUiXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm1kb2MucmVzaWRlbnRfc3RyZWV0Il0sImludGVudF90b19y
            ZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJC5tZG9jLnJlc2lkZW50X2hvdXNlX251bWJlciJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0s
            eyJwYXRoIjpbIiQubWRvYy5nZW5kZXIiXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm1kb2MubmF0aW9uYWxpdHki
            XSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm1kb2MuaXNzdWFuY2VfZGF0ZSJdLCJpbnRlbnRfdG9fcmV0YWluIjpm
            YWxzZX0seyJwYXRoIjpbIiQubWRvYy5leHBpcnlfZGF0ZSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQubWRvYy5p
            c3N1aW5nX2F1dGhvcml0eSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQubWRvYy5kb2N1bWVudF9udW1iZXIiXSwi
            aW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm1kb2MuYWRtaW5pc3RyYXRpdmVfbnVtYmVyIl0sImludGVudF90b19yZXRh
            aW4iOmZhbHNlfSx7InBhdGgiOlsiJC5tZG9jLmlzc3VpbmdfY291bnRyeSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpb
            IiQubWRvYy5pc3N1aW5nX2p1cmlzZGljdGlvbiJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX1dfX1dfSwic3RhdGUiOiJXTEZKRW45QUdi
            SmZBY0V5YVFUenp4dWVxbWVSYXptc0hJa3hNUlRrR1JMMXp5STd1bi1LSldhWHR1bHJmaVNTMzhMbFU1QUJEQjlaZHNmcV8xMXI4USIsImlh
            dCI6MTcxMDc2NjI5NCwiY2xpZW50X21ldGFkYXRhIjp7ImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZyI6IkVDREgtRVMi
            LCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9lbmMiOiJBMTI4Q0JDLUhTMjU2IiwiaWRfdG9rZW5fZW5jcnlwdGVkX3Jlc3Bv
            bnNlX2FsZyI6IlJTQS1PQUVQLTI1NiIsImlkX3Rva2VuX2VuY3J5cHRlZF9yZXNwb25zZV9lbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiandrc191
            cmkiOiJodHRwczovL3ZlcmlmaWVyLWJhY2tlbmQuZXVkaXcuZGV2L3dhbGxldC9qYXJtL1dMRkpFbjlBR2JKZkFjRXlhUVR6enh1ZXFtZVJh
            em1zSElreE1SVGtHUkwxenlJN3VuLUtKV2FYdHVscmZpU1MzOExsVTVBQkRCOVpkc2ZxXzExcjhRL2p3a3MuanNvbiIsInN1YmplY3Rfc3lu
            dGF4X3R5cGVzX3N1cHBvcnRlZCI6WyJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1icHJpbnQiXSwiaWRfdG9rZW5fc2lnbmVkX3Jl
            c3BvbnNlX2FsZyI6IlJTMjU2In19.a5UzXIoRZzNQFAWFblAhkYocrR05hB-GIO7nRdqRnFrqxjvBVP6HfFhPyASRmhSgE0vUe0TPN0-TbQk
            Yh0-LeA
        """.trimIndent()

        val jwkset = """
            {
                "keys": [
                    {
                        "alg": "ECDH-ES",
                        "crv": "P-256",
                        "kid": "1835c633-bd3f-429e-8dfa-64596b83aa0c",
                        "kty": "EC",
                        "use": "enc",
                        "x": "lBeONku60ShqCvndUdFVubOCCuvMjWTmElaxgHWbuMo",
                        "y": "NHYLE--QpTqc9vGrTLoq1dm2c86AC6af6xiHiLpKjdk"
                    }
                ]
            }

        """.trimIndent()

        holderSiop = OidcSiopWallet.newInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService,
            remoteResourceRetriever = {
                if (it == "https://verifier-backend.eudiw.dev/wallet/jarm/" +
                    "WLFJEn9AGbJfAcEyaQTzzxueqmeRazmsHIkxMRTkGRL1zyI7un-KJWaXtulrfiSS38LlU5ABDB9Zdsfq_11r8Q/jwks.json"
                ) jwkset else if (it == "https://verifier-backend.eudiw.dev/wallet/request.jwt/" +
                    "WLFJEn9AGbJfAcEyaQTzzxueqmeRazmsHIkxMRTkGRL1zyI7un-KJWaXtulrfiSS38LlU5ABDB9Zdsfq_11r8Q"
                ) requestObject else null
            }
        )

        val response = holderSiop.createAuthnResponse(url).getOrThrow()

        response.shouldBeInstanceOf<AuthenticationResponseResult.Post>()
        val jarmParams = response.params.formUrlEncode().decodeFromPostBody<AuthenticationResponseParameters>()
        val jarm = jarmParams.response
        jarm.shouldNotBeNull()
        val params = AuthenticationResponseParameters.deserialize(JwsSigned.parse(jarm)!!.payload.decodeToString())
        params.shouldNotBeNull()
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

})



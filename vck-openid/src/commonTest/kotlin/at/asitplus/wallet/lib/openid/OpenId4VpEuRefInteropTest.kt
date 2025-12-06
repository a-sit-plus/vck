package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.subjectAltName_2_5_29_17
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.pki.SubjectAltNameImplicitTags
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSingleElement
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Instant

/**
 * Tests our OpenId4VP implementation against EUDI Ref Impl.,
 * see [https://verifier.eudiw.dev/cbor-selectable/verifiable](https://verifier.eudiw.dev/cbor-selectable/verifiable)
 */
@Suppress("DEPRECATION")
val OpenId4VpEuRefInteropTest by testSuite {
    withFixtureGenerator(suspend {
        val holderKeyMaterial = EphemeralKeyWithoutCert()
        val agent = HolderAgent(holderKeyMaterial).also {
            val issuerAgent = IssuerAgent(
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            )
            it.storeCredential(
                issuerAgent.issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        holderKeyMaterial.publicKey,
                        EuPidScheme,
                        ConstantIndex.CredentialRepresentation.SD_JWT,
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            )
            it.storeCredential(
                issuerAgent.issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        holderKeyMaterial.publicKey,
                        ConstantIndex.AtomicAttribute2023,
                        ConstantIndex.CredentialRepresentation.SD_JWT,
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            )
        }
        object {
            val holderKeyMaterial = holderKeyMaterial
            val holderAgent = agent
            var holderOid4vp = OpenId4VpHolder(holderKeyMaterial, holderAgent, randomSource = RandomSource.Default)
        }
    }) - {

        "EUDI from URL 2024-05-17" {
            val url = """
            eudi-openid4vp://verifier-backend.eudiw.dev?client_id=verifier-backend.eudiw.dev&request_uri=https%3A%2F%2Fverifier-backend.eudiw.dev%2Fwallet%2Frequest.jwt%2FVu3g2FXDeqday-wS0Xmty0bYzzq3MeVGrPSGTdk3Y60tWNLHkr_bg9WJMK3xktNsqWpEXPsDgBw5g3r80MQyTw
        """.trimIndent().replace("\n", "")

            val requestObject = """
        eyJ4NWMiOlsiTUlJREtqQ0NBckNnQXdJQkFnSVVmeTl1NlNMdGdOdWY5UFhZYmgvUURxdVh6NTB3Q2dZSUtvWkl6ajBFQXdJd1hERWVNQndHQTFV
        RUF3d1ZVRWxFSUVsemMzVmxjaUJEUVNBdElGVlVJREF4TVMwd0t3WURWUVFLRENSRlZVUkpJRmRoYkd4bGRDQlNaV1psY21WdVkyVWdTVzF3YkdW
        dFpXNTBZWFJwYjI0eEN6QUpCZ05WQkFZVEFsVlVNQjRYRFRJME1ESXlOakF5TXpZek0xb1hEVEkyTURJeU5UQXlNell6TWxvd2FURWRNQnNHQTFV
        RUF3d1VSVlZFU1NCU1pXMXZkR1VnVm1WeWFXWnBaWEl4RERBS0JnTlZCQVVUQXpBd01URXRNQ3NHQTFVRUNnd2tSVlZFU1NCWFlXeHNaWFFnVW1W
        bVpYSmxibU5sSUVsdGNHeGxiV1Z1ZEdGMGFXOXVNUXN3Q1FZRFZRUUdFd0pWVkRCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQk1i
        V0JBQzFHaitHRE8veUNTYmdiRndwaXZQWVdMekV2SUxOdGRDdjdUeDFFc3hQQ3hCcDNEWkI0RklyNEJsbVZZdEdhVWJvVklpaFJCaVFEbzNNcFdp
        amdnRkJNSUlCUFRBTUJnTlZIUk1CQWY4RUFqQUFNQjhHQTFVZEl3UVlNQmFBRkxOc3VKRVhITmVrR21ZeGgwTGhpOEJBekpVYk1DVUdBMVVkRVFR
        ZU1CeUNHblpsY21sbWFXVnlMV0poWTJ0bGJtUXVaWFZrYVhjdVpHVjJNQklHQTFVZEpRUUxNQWtHQnlpQmpGMEZBUVl3UXdZRFZSMGZCRHd3T2pB
        NG9EYWdOSVl5YUhSMGNITTZMeTl3Y21Wd2NtOWtMbkJyYVM1bGRXUnBkeTVrWlhZdlkzSnNMM0JwWkY5RFFWOVZWRjh3TVM1amNtd3dIUVlEVlIw
        T0JCWUVGRmdtQWd1QlN2U25tNjhaem81SVN0SXYyZk0yTUE0R0ExVWREd0VCL3dRRUF3SUhnREJkQmdOVkhSSUVWakJVaGxKb2RIUndjem92TDJk
        cGRHaDFZaTVqYjIwdlpYVXRaR2xuYVhSaGJDMXBaR1Z1ZEdsMGVTMTNZV3hzWlhRdllYSmphR2wwWldOMGRYSmxMV0Z1WkMxeVpXWmxjbVZ1WTJV
        dFpuSmhiV1YzYjNKck1Bb0dDQ3FHU000OUJBTUNBMmdBTUdVQ01RREdmZ0xLbmJLaGlPVkYzeFNVMGFlanUvbmVHUVVWdU5ic1F3MExlRER3SVcr
        ckxhdGViUmdvOWhNWERjM3dybFVDTUFJWnlKN2xSUlZleU1yM3dqcWtCRjJsOVliMHdPUXBzblpCQVZVQVB5STV4aFdYMlNBYXpvbTJKanNOL2FL
        QWtRPT0iLCJNSUlESFRDQ0FxT2dBd0lCQWdJVVZxamd0SnFmNGhVWUprcWRZemkrMHh3aHdGWXdDZ1lJS29aSXpqMEVBd013WERFZU1Cd0dBMVVF
        QXd3VlVFbEVJRWx6YzNWbGNpQkRRU0F0SUZWVUlEQXhNUzB3S3dZRFZRUUtEQ1JGVlVSSklGZGhiR3hsZENCU1pXWmxjbVZ1WTJVZ1NXMXdiR1Z0
        Wlc1MFlYUnBiMjR4Q3pBSkJnTlZCQVlUQWxWVU1CNFhEVEl6TURrd01URTRNelF4TjFvWERUTXlNVEV5TnpFNE16UXhObG93WERFZU1Cd0dBMVVF
        QXd3VlVFbEVJRWx6YzNWbGNpQkRRU0F0SUZWVUlEQXhNUzB3S3dZRFZRUUtEQ1JGVlVSSklGZGhiR3hsZENCU1pXWmxjbVZ1WTJVZ1NXMXdiR1Z0
        Wlc1MFlYUnBiMjR4Q3pBSkJnTlZCQVlUQWxWVU1IWXdFQVlIS29aSXpqMENBUVlGSzRFRUFDSURZZ0FFRmc1U2hmc3hwNVIvVUZJRUtTM0wyN2R3
        bkZobmpTZ1VoMmJ0S09RRW5mYjNkb3llcU1BdkJ0VU1sQ2xoc0YzdWVmS2luQ3cwOE5CMzFyd0MrZHRqNlgvTEUzbjJDOWpST0lVTjhQcm5sTFM1
        UXM0UnM0WlU1T0lnenRvYU84RzlvNElCSkRDQ0FTQXdFZ1lEVlIwVEFRSC9CQWd3QmdFQi93SUJBREFmQmdOVkhTTUVHREFXZ0JTemJMaVJGeHpY
        cEJwbU1ZZEM0WXZBUU15Vkd6QVdCZ05WSFNVQkFmOEVEREFLQmdncmdRSUNBQUFCQnpCREJnTlZIUjhFUERBNk1EaWdOcUEwaGpKb2RIUndjem92
        TDNCeVpYQnliMlF1Y0d0cExtVjFaR2wzTG1SbGRpOWpjbXd2Y0dsa1gwTkJYMVZVWHpBeExtTnliREFkQmdOVkhRNEVGZ1FVczJ5NGtSY2MxNlFh
        WmpHSFF1R0x3RURNbFJzd0RnWURWUjBQQVFIL0JBUURBZ0VHTUYwR0ExVWRFZ1JXTUZTR1VtaDBkSEJ6T2k4dloybDBhSFZpTG1OdmJTOWxkUzFr
        YVdkcGRHRnNMV2xrWlc1MGFYUjVMWGRoYkd4bGRDOWhjbU5vYVhSbFkzUjFjbVV0WVc1a0xYSmxabVZ5Wlc1alpTMW1jbUZ0WlhkdmNtc3dDZ1lJ
        S29aSXpqMEVBd01EYUFBd1pRSXdhWFVBM2orK3hsL3RkRDc2dFhFV0Npa2ZNMUNhUno0dnpCQzdOUzB3Q2RJdEtpejZIWmVWOEVQdE5DbnNmS3BO
        QWpFQXFyZGVLRG5yNUt3ZjhCQTd0QVRlaHhObE9WNEhuYzEwWE8xWFVMdGlnQ3diNDlScGtxbFMySHVsK0RwcU9iVXMiXSwidHlwIjoib2F1dGgt
        YXV0aHotcmVxK2p3dCIsImFsZyI6IkVTMjU2In0.eyJyZXNwb25zZV91cmkiOiJodHRwczovL3ZlcmlmaWVyLWJhY2tlbmQuZXVkaXcuZGV2L3dh
        bGxldC9kaXJlY3RfcG9zdCIsImNsaWVudF9pZF9zY2hlbWUiOiJ4NTA5X3Nhbl9kbnMiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJub25j
        ZSI6ImRhNDE0YWJhLTM3NjktNGMzZC1iMGZhLWI5MGZmNTM2ZDc3YSIsImNsaWVudF9pZCI6InZlcmlmaWVyLWJhY2tlbmQuZXVkaXcuZGV2Iiwi
        cmVzcG9uc2VfbW9kZSI6ImRpcmVjdF9wb3N0Lmp3dCIsImF1ZCI6Imh0dHBzOi8vc2VsZi1pc3N1ZWQubWUvdjIiLCJzY29wZSI6IiIsInByZXNl
        bnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiMzJmNTQxNjMtNzE2Ni00OGYxLTkzZDgtZmYyMTdiZGIwNjUzIiwiaW5wdXRfZGVzY3JpcHRvcnMi
        Olt7ImlkIjoiZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xIiwibmFtZSI6IkVVREkgUElEIiwicHVycG9zZSI6IldlIG5lZWQgdG8gdmVyaWZ5IHlv
        dXIgaWRlbnRpdHkiLCJmb3JtYXQiOnsibXNvX21kb2MiOnsiYWxnIjpbIkVTMjU2IiwiRVMzODQiLCJFUzUxMiIsIkVkRFNBIiwiRVNCMjU2Iiwi
        RVNCMzIwIiwiRVNCMzg0IiwiRVNCNTEyIl19fSwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRp
        dy5waWQuMSddWydmYW1pbHlfbmFtZSddIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJFsnZXUuZXVyb3BhLmVjLmV1ZGl3
        LnBpZC4xJ11bJ2dpdmVuX25hbWUnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5w
        aWQuMSddWydiaXJ0aF9kYXRlJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkWydldS5ldXJvcGEuZWMuZXVkaXcucGlk
        LjEnXVsnYWdlX292ZXJfMTgnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQu
        MSddWydhZ2VfaW5feWVhcnMnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQu
        MSddWydhZ2VfYmlydGhfeWVhciddIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJFsnZXUuZXVyb3BhLmVjLmV1ZGl3LnBp
        ZC4xJ11bJ2ZhbWlseV9uYW1lX2JpcnRoJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkWydldS5ldXJvcGEuZWMuZXVk
        aXcucGlkLjEnXVsnZ2l2ZW5fbmFtZV9iaXJ0aCddIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJFsnZXUuZXVyb3BhLmVj
        LmV1ZGl3LnBpZC4xJ11bJ2JpcnRoX3BsYWNlJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkWydldS5ldXJvcGEuZWMu
        ZXVkaXcucGlkLjEnXVsnYmlydGhfY291bnRyeSddIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJFsnZXUuZXVyb3BhLmVj
        LmV1ZGl3LnBpZC4xJ11bJ2JpcnRoX3N0YXRlJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkWydldS5ldXJvcGEuZWMu
        ZXVkaXcucGlkLjEnXVsnYmlydGhfY2l0eSddIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJFsnZXUuZXVyb3BhLmVjLmV1
        ZGl3LnBpZC4xJ11bJ3Jlc2lkZW50X2FkZHJlc3MnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ2V1LmV1cm9wYS5l
        Yy5ldWRpdy5waWQuMSddWydyZXNpZGVudF9jb3VudHJ5J10iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkWydldS5ldXJv
        cGEuZWMuZXVkaXcucGlkLjEnXVsncmVzaWRlbnRfc3RhdGUnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiRbJ2V1LmV1
        cm9wYS5lYy5ldWRpdy5waWQuMSddWydyZXNpZGVudF9jaXR5J10iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkWydldS5l
        dXJvcGEuZWMuZXVkaXcucGlkLjEnXVsncmVzaWRlbnRfcG9zdGFsX2NvZGUnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpb
        IiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQuMSddWydyZXNpZGVudF9zdHJlZXQnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRo
        IjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQuMSddWydyZXNpZGVudF9ob3VzZV9udW1iZXInXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxz
        ZX0seyJwYXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQuMSddWydnZW5kZXInXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJw
        YXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQuMSddWyduYXRpb25hbGl0eSddIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBh
        dGgiOlsiJFsnZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xJ11bJ2lzc3VhbmNlX2RhdGUnXSJdLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJw
        YXRoIjpbIiRbJ2V1LmV1cm9wYS5lYy5ldWRpdy5waWQuMSddWydleHBpcnlfZGF0ZSddIl0sImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBh
        dGgiOlsiJFsnZXUuZXVyb3BhLmVjLmV1ZGl3LnBpZC4xJ11bJ2lzc3VpbmdfYXV0aG9yaXR5J10iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9
        LHsicGF0aCI6WyIkWydldS5ldXJvcGEuZWMuZXVkaXcucGlkLjEnXVsnZG9jdW1lbnRfbnVtYmVyJ10iXSwiaW50ZW50X3RvX3JldGFpbiI6ZmFs
        c2V9LHsicGF0aCI6WyIkWydldS5ldXJvcGEuZWMuZXVkaXcucGlkLjEnXVsnYWRtaW5pc3RyYXRpdmVfbnVtYmVyJ10iXSwiaW50ZW50X3RvX3Jl
        dGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkWydldS5ldXJvcGEuZWMuZXVkaXcucGlkLjEnXVsnaXNzdWluZ19jb3VudHJ5J10iXSwiaW50ZW50X3Rv
        X3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkWydldS5ldXJvcGEuZWMuZXVkaXcucGlkLjEnXVsnaXNzdWluZ19qdXJpc2RpY3Rpb24nXSJdLCJp
        bnRlbnRfdG9fcmV0YWluIjpmYWxzZX1dfX1dfSwic3RhdGUiOiJWdTNnMkZYRGVxZGF5LXdTMFhtdHkwYll6enEzTWVWR3JQU0dUZGszWTYwdFdO
        TEhrcl9iZzlXSk1LM3hrdE5zcVdwRVhQc0RnQnc1ZzNyODBNUXlUdyIsImlhdCI6MTcxNTk0MTk0OSwiY2xpZW50X21ldGFkYXRhIjp7ImF1dGhv
        cml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZyI6IkVDREgtRVMiLCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9lbmMiOiJB
        MTI4Q0JDLUhTMjU2IiwiaWRfdG9rZW5fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZyI6IlJTQS1PQUVQLTI1NiIsImlkX3Rva2VuX2VuY3J5cHRlZF9y
        ZXNwb25zZV9lbmMiOiJBMTI4Q0JDLUhTMjU2Iiwiandrc191cmkiOiJodHRwczovL3ZlcmlmaWVyLWJhY2tlbmQuZXVkaXcuZGV2L3dhbGxldC9q
        YXJtL1Z1M2cyRlhEZXFkYXktd1MwWG10eTBiWXp6cTNNZVZHclBTR1RkazNZNjB0V05MSGtyX2JnOVdKTUszeGt0TnNxV3BFWFBzRGdCdzVnM3I4
        ME1ReVR3L2p3a3MuanNvbiIsInN1YmplY3Rfc3ludGF4X3R5cGVzX3N1cHBvcnRlZCI6WyJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6andrLXRodW1i
        cHJpbnQiXSwiaWRfdG9rZW5fc2lnbmVkX3Jlc3BvbnNlX2FsZyI6IlJTMjU2In19.r2P3d4r6PxPW_Xz7npvf9rfGMzxx5ehDZMkEg1YrlRftOGX
        jwCtloSDgk1LwO-Fwd7HYBaDbZtkbpFkWhSU7Vw
        """.trimIndent()

            val jwkset = """
        {
            "keys": [
                {
                    "alg": "ECDH-ES",
                    "crv": "P-256",
                    "kid": "ad1cc909-b497-46ed-b209-e1f8b6fc866a",
                    "kty": "EC",
                    "use": "enc",
                    "x": "4oEq9dAc8mtGpB92sq5Ntzvos2PVqP7WF3oBNuJCIog",
                    "y": "a8HrJbkCbWp5GdkJE94u20cfmj-Qm7ubm2FBQs3xKKE"
                }
            ]
        }
        """.trimIndent()

            val jwksUrl =
                "https://verifier-backend.eudiw.dev/wallet/jarm/Vu3g2FXDeqday-wS0Xmty0bYzzq3MeVGrPSGTdk3Y60tWNLHkr_bg9WJMK3xktNsqWpEXPsDgBw5g3r80MQyTw/jwks.json"
            val requestUrl =
                "https://verifier-backend.eudiw.dev/wallet/request.jwt/Vu3g2FXDeqday-wS0Xmty0bYzzq3MeVGrPSGTdk3Y60tWNLHkr_bg9WJMK3xktNsqWpEXPsDgBw5g3r80MQyTw"
            it.holderOid4vp = OpenId4VpHolder(
                holder = it.holderAgent,
                remoteResourceRetriever = {
                    if (it.url == jwksUrl) jwkset else if (it.url == requestUrl) requestObject else null
                },
                randomSource = RandomSource.Default,
            )

            it.holderOid4vp.startAuthorizationResponsePreparation(url).getOrThrow()
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
                                        "$.mdoc.doctype"
                                    ],
                                    "filter": {
                                        "type": "string",
                                        "const": "eu.europa.ec.eudiw.pid.1"
                                    }
                                },
                                {
                                    "path": [
                                        "$.mdoc.namespace"
                                    ],
                                    "filter": {
                                        "type": "string",
                                        "const": "eu.europa.ec.eudiw.pid.1"
                                    }
                                },
                                {
                                    "path": [
                                        "$.mdoc.given_name"
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

            val parsed = vckJsonSerializer.decodeFromString<AuthenticationRequestParameters>(input)
            parsed.shouldNotBeNull()

            parsed.responseUrl shouldBe "https://verifier-backend.eudiw.dev/wallet/direct_post"
            parsed.responseType shouldBe "vp_token"
            parsed.nonce shouldBe "nonce"
            parsed.clientId shouldBe "verifier-backend.eudiw.dev"
            parsed.clientIdWithoutPrefix shouldBe "verifier-backend.eudiw.dev"
            parsed.responseMode shouldBe OpenIdConstants.ResponseMode.DirectPostJwt
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
            parsed.issuedAt shouldBe Instant.Companion.fromEpochSeconds(1710313534)
            val cm = parsed.clientMetadata
            cm.shouldNotBeNull()
            cm.subjectSyntaxTypesSupported.shouldNotBeNull() shouldHaveSingleElement "urn:ietf:params:oauth:jwk-thumbprint"
            cm.authorizationEncryptedResponseAlg shouldBe JweAlgorithm.ECDH_ES
            cm.authorizationEncryptedResponseEncoding shouldBe JweEncryption.A128CBC_HS256
            cm.idTokenEncryptedResponseAlg shouldBe JweAlgorithm.RSA_OAEP_256
            cm.idTokenEncryptedResponseEncoding shouldBe JweEncryption.A128CBC_HS256
            cm.idTokenSignedResponseAlg shouldBe JwsAlgorithm.Signature.RS256
            cm.jsonWebKeySetUrl shouldBe "https://verifier-backend.eudiw.dev/wallet/jarm/" +
                    "xgagB1vsIrWhMLixoJTCVZZvOHsZ8QrulEFxc0bjJdMRyzqO6j2-UB00gmOZraocfoknlxXY-kaoLlX8kygqxw/jwks.json"
        }

        "Request in request URI" {
            val input = "mdoc-openid4vp://?client_id=https://example.com/ef391e30-bacc-4441-af5d-7f42fb682e02" +
                    "&request_uri=https%3A%2F%2Fexample.com%2Fd15b5b6f-7821-4031-9a18-ebe491b720a6"
            val signer = SignJwt<AuthenticationRequestParameters>(EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk())
            val jws = signer(
                JwsContentTypeConstants.OAUTH_AUTHZ_REQUEST,
                AuthenticationRequestParameters(
                    nonce = "RjEQKQeG8OUaKT4ij84E8mCvry6pVSgDyqRBMW5eBTPItP4DIfbKaT6M6v6q2Dvv8fN7Im7Ifa6GI2j6dHsJaQ==",
                    state = "ef391e30-bacc-4441-af5d-7f42fb682e02",
                    responseUrl = "https://example.com/ef391e30-bacc-4441-af5d-7f42fb682e02",
                    clientId = "https://example.com/ef391e30-bacc-4441-af5d-7f42fb682e02",
                    responseType = "vp_token",
                ),
                AuthenticationRequestParameters.serializer(),
            ).getOrThrow().serialize()

            val wallet = OpenId4VpHolder(
                remoteResourceRetriever = {
                    if (it.url == "https://example.com/d15b5b6f-7821-4031-9a18-ebe491b720a6") jws else null
                },
                randomSource = RandomSource.Default,
            )

            wallet.startAuthorizationResponsePreparation(input).getOrThrow().apply {
                request.parameters.state shouldBe "ef391e30-bacc-4441-af5d-7f42fb682e02"
                request.parameters.responseUrl shouldBe "https://example.com/ef391e30-bacc-4441-af5d-7f42fb682e02"
                request.parameters.clientIdWithoutPrefix shouldBe request.parameters.responseUrl
            }
        }

        "process with cross-device flow with request_uri and x509_san_dns" {
            val clientId = "example.com"
            val extensions = listOf(
                X509CertificateExtension(
                    KnownOIDs.subjectAltName_2_5_29_17,
                    critical = false,
                    Asn1EncapsulatingOctetString(
                        listOf(
                            Asn1.Sequence {
                                +Asn1Primitive(
                                    SubjectAltNameImplicitTags.dNSName,
                                    Asn1String.UTF8(clientId).encodeToTlv().content
                                )
                            }
                        ))))
            val verifierKeyMaterial = EphemeralKeyWithSelfSignedCert(extensions = extensions)
            val verifierOid4vp = OpenId4VpVerifier(
                keyMaterial = verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.CertificateSanDns(
                    listOf(verifierKeyMaterial.getCertificate()!!),
                    clientId,
                    clientId
                ),
            )
            val nonce = uuid4().toString()
            val requestUrl = "https://example.com/request/$nonce"
            val (walletUrl, jar) = verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    responseMode = OpenIdConstants.ResponseMode.DirectPost,
                    responseUrl = "https://example.com/response",
                    credentials = setOf(
                        RequestOptionsCredential(
                            ConstantIndex.AtomicAttribute2023,
                            ConstantIndex.CredentialRepresentation.SD_JWT,
                            setOf(CLAIM_FAMILY_NAME, CLAIM_GIVEN_NAME)
                        )
                    )
                ),
                OpenId4VpVerifier.CreationOptions.SignedRequestByReference("https://wallet.a-sit.at/mobile", requestUrl)
            ).getOrThrow()
            jar.shouldNotBeNull()

            it.holderOid4vp = OpenId4VpHolder(
                keyMaterial = it.holderKeyMaterial,
                holder = it.holderAgent,
                remoteResourceRetriever = {
                    if (it.url == requestUrl) jar.invoke(it.requestObjectParameters).getOrThrow() else null
                },
                randomSource = RandomSource.Default,
            )

            val state = it.holderOid4vp.startAuthorizationResponsePreparation(walletUrl).getOrThrow()
            val response = it.holderOid4vp.finalizeAuthorizationResponse(state).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()
            verifierOid4vp.validateAuthnResponse(response.params.formUrlEncode())
                .shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
        }
    }
}

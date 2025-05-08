package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.datetime.Instant

class AgentSdJwtInteropTest : FreeSpec({

    lateinit var holder: Holder
    lateinit var holderCredentialStore: SubjectCredentialStore
    lateinit var holderKeyMaterial: KeyMaterial

    beforeEach {
        holderCredentialStore = InMemorySubjectCredentialStore()
        holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
        val certificate = """
            MIIBhTCCASugAwIBAgIUC2Xrc41w9o2CY+4lhyLQWueaKGAwCgYIKoZIzj0EAwIw
            GDEWMBQGA1UEAwwNcGlkLXV0LWlzc3VlcjAeFw0yNDEwMjQxMTUxNDhaFw0yNDEx
            MjMxMTUxNDhaMBgxFjAUBgNVBAMMDXBpZC11dC1pc3N1ZXIwWTATBgcqhkjOPQIB
            BggqhkjOPQMBBwNCAARrAGINez4vmjXMRDiN1fBzlZy/VvSADnAoVeMrUpR6aNj9
            ehraMttTPfGPb3uHPvTPJfigZ6lyFaybWhTreMxjo1MwUTAdBgNVHQ4EFgQUbZ3T
            spfdJbLHnIeZOf7ECGjhR1swHwYDVR0jBBgwFoAUbZ3TspfdJbLHnIeZOf7ECGjh
            R1swDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiAPjQ+C2gKZhxCS
            rwFVp5Mm8Dv+L0n4c+X/iUH1HYuayQIhALynPbzWFaLZ5C/L085DdcdKwm2VVh79
            vFasslXfxmLJ
            """.trimIndent().replace("\n", "")
        val publicKey = X509Certificate.decodeFromByteArray(certificate.decodeToByteArray(Base64()))!!.publicKey
        holder = HolderAgent(
            holderKeyMaterial,
            holderCredentialStore,
            validator = Validator(
                verifyJwsObject = VerifyJwsObject(publicKeyLookup = { setOf(publicKey.toJsonWebKey()) }),
                parser = Parser(clock = FixedTimeClock(Instant.parse("2025-01-01T07:48:04Z").toEpochMilliseconds()))
            )
        )
    }

    "accepts credential from EUDIW issuer" {
        val input = """
            eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0
            .eyJpc3MiOiAiaHR0cHM6Ly8xOTIuMTY4LjkwLjE3Nzo1MDAwIiwgImp0aSI6ICIxYWEyNTczYy0yNWZiLTQzODctYmRiZC1iN2JhODQ4MzI
            4ZTUiLCAiaWF0IjogMTczMDA3MDAwMCwgImV4cCI6IDE3Mzc4NDYwMDAsICJ2Y3QiOiAiZXUuZXVyb3BhLmVjLmV1ZGkucGlkLjEiLCAidmV
            yaWZpZWRfY2xhaW1zIjogeyJ2ZXJpZmljYXRpb24iOiB7Il9zZCI6IFsiU1BKeDFvWGo4Nm8yTjd3RDhGdllGUHdia3A1UC0zYmFHcHIxWnh
            uMmNpOCJdLCAidHJ1c3RfZnJhbWV3b3JrIjogImVpZGFzIiwgImFzc3VyYW5jZV9sZXZlbCI6ICJoaWdoIn0sICJjbGFpbXMiOiB7ImV1LmV
            1cm9wYS5lYy5ldWRpLnBpZC4xIjogeyJfc2QiOiBbIjNLY2kxX09leVptdmkxY1RnS0I2OTdVYWpDVDFwRlNGRzQzdUt2WVktNGMiLCAiQWJ
            iZkZwR0xfdHJob2tUaEx0UE41M0tvQTcwVDNpTE1OMVpmYk9pQV9YTSIsICJFNWNMNlRWMExfN1FZa25FYzQ0UVZnWkVDTnY1VTZCYThmcXc
            wZTNIY1owIiwgIkdJTGg5YVhQZHBXQ2FJcjdsU0haVTB0bEFPVVF3RmdCOWllWlZrTHlOMjQiLCAiTUNMZndVdWxnaFpFOU42ZFVXdFg3dlh
            NbWtZby1rSks1YmExODZ2el9LSSIsICJOejQySW9KXzh6VGJ4dTRpdE52cHlIU3hsOHV5eUxyaXpQMlNuQ3hKZXFBIiwgIlNLM0JWNWlDaXQ
            2aVAtNjRiVS1Ib3VFQlV4Y0o1VkZjZ1hiS1luWlBla28iLCAiWktDSzJTT0NQSDF3ZGtzWktZckJudEZhTl8yZUVzUE82Tld5dFhDVXlWcyJ
            dfX19LCAiX3NkX2FsZyI6ICJzaGEtMjU2IiwgImNuZiI6IHsiandrIjogeyJrdHkiOiAiRUMiLCAiY3J2IjogIlAtMjU2IiwgIngiOiAiVzJ
            fWjRyRS1zT1ZvZkNab0tCdWk0QXQwcEsySGo3aVJKZk5JbkY5dVMtMCIsICJ5IjogInRjaHpodEJldi01djRkcDY4MU1Pam1XYWNCVlBrY1d
            VMFBsVDBYWkRENTAifX19
            .8RfeOFDzoe0RvlCrNWcJr5yJOQhaGJc6edtwOhRR3nN3OwMI5dWTQQFlT3RPfzxbUz14y4RQv48BtrFDtPN0dg
            ~WyJ2TGdMZ19zUjZYb0d6M2swSkJ0cUNRIiwgImV2aWRlbmNlIiwgeyJ0eXBlIjogImV1LmV1cm9wYS5lYy5ldWRpLnBpZC4xIiwgInNvdXJ
            jZSI6IHsib3JnYW5pemF0aW9uX25hbWUiOiAiVGVzdCBQSUQgaXNzdWVyIiwgIm9yZ2FuaXphdGlvbl9pZCI6ICJFVURJIFdhbGxldCBSZWZ
            lcmVuY2UgSW1wbGVtZW50YXRpb24iLCAiY291bnRyeV9jb2RlIjogIkZDIn19XQ
            ~WyJhUWxaN2I2bHJZVnA3Wk9INHUzY2VBIiwgImZhbWlseV9uYW1lIiwgImZhbWlseSJd
            ~WyJBX2VjM1Y3Ym5WNjR1aU0zaE5VbU93IiwgImdpdmVuX25hbWUiLCAiR2l2ZW4iXQ
            ~WyJRbXpmTjRidkl0ZUFFakFOWTdYeGRBIiwgImJpcnRoX2RhdGUiLCAiMjAyNC0xMC0wNCJd
            ~WyJycnlUdV82WmduajRDcVVETEZ5U1J3IiwgImFnZV9vdmVyXzE4IiwgZmFsc2Vd
            ~WyJaNi1weFRDR1I2ZEZ3QXVzMTBXeE1BIiwgImlzc3VhbmNlX2RhdGUiLCAiMjAyNC0xMC0yOCJd
            ~WyJXOWl6eGJmZXVsZnFNb3NyRUo3VDFnIiwgImV4cGlyeV9kYXRlIiwgIjIwMjUtMDEtMjYiXQ
            ~WyJPRDRZNXZQM05YMGI2VUV4ZEdpNDdRIiwgImlzc3VpbmdfYXV0aG9yaXR5IiwgIlRlc3QgUElEIGlzc3VlciJd
            ~WyJZdHR0Z2lFb2dzXzlEaDFHZWtjNnVnIiwgImlzc3VpbmdfY291bnRyeSIsICJGQyJd
            ~
        """.trimIndent().replace("\n", "")

        val stored = holder.storeCredential(
            Holder.StoreCredentialInput.SdJwt(input, EuPidScheme)
        ).getOrThrow()

        val entry = stored.storeEntry
        entry.shouldBeInstanceOf<SubjectCredentialStore.StoreEntry.SdJwt>()
        entry.disclosures.size shouldBe 9

        val expectedJson = """
            {
                "iss": "https://192.168.90.177:5000",
                "jti": "1aa2573c-25fb-4387-bdbd-b7ba848328e5",
                "iat": 1730070000,
                "exp": 1737846000,
                "vct": "eu.europa.ec.eudi.pid.1",
                "verified_claims": {
                    "verification": {
                        "evidence": {
                            "type": "eu.europa.ec.eudi.pid.1",
                            "source": {
                                "organization_name": "Test PID issuer",
                                "organization_id": "EUDI Wallet Reference Implementation",
                                "country_code": "FC"
                            }
                        },
                        "trust_framework": "eidas",
                        "assurance_level": "high"
                    },
                    "claims": {
                        "eu.europa.ec.eudi.pid.1": {
                            "expiry_date": "2025-01-26",
                            "family_name": "family",
                            "age_over_18": false,
                            "issuing_authority": "Test PID issuer",
                            "issuance_date": "2024-10-28",
                            "given_name": "Given",
                            "birth_date": "2024-10-04",
                            "issuing_country": "FC"
                        }
                    }
                },
                "cnf": {
                    "jwk": {
                        "kty": "EC",
                        "crv": "P-256",
                        "x": "W2_Z4rE-sOVofCZoKBui4At0pK2Hj7iRJfNInF9uS-0",
                        "y": "tchzhtBev-5v4dp681MOjmWacBVPkcWU0PlT0XZDD50"
                    }
                }
            }
        """.trimIndent().let { vckJsonSerializer.parseToJsonElement(it) }
        SdJwtValidator(SdJwtSigned.parse(entry.vcSerialized)!!).reconstructedJsonObject shouldBe expectedJson
    }

})
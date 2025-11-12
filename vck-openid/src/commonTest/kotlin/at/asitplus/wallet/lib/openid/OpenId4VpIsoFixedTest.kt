package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSingleElement
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.provided.at.asitplus.wallet.lib.openid.FixedNonceService
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray

/**
 * Tests the the verifier from [OpenId4VpIsoProtocolTest] with a fixed response,
 * i.e. in the currently defined format of the device signature and session transcript for ISO mdocs,
 * that is the definition from ISO/IEC 18013-7:2024 Annex B.
 */
val OpenId4VpIsoFixedTest by testSuite {

    "Selective Disclosure with mDL (ISO/IEC 18013-7:2024 Annex B)" {
        val keyDerBase64 =
        "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBSDNqIQFkUOAyOLd6Xy2zcF7UlgvQAKM8qsOUO41eelw=="
        val verifierKeyMaterial = FixedKeyMaterial(keyDerBase64.decodeToByteArray(Base64Strict))
        val clientId = "https://example.com/rp/7db83193-90f8-4c57-89b6-68c104e90067"

//        variable authnRequest has been generated with this code:
//
//        val requestOptions = RequestOptions(
//            credentials = setOf(
//                RequestOptionsCredential(
//                    MobileDrivingLicenceScheme,
//                    ConstantIndex.CredentialRepresentation.ISO_MDOC,
//                    setOf(requestedClaim)
//                )
//            ),
//            responseMode = OpenIdConstants.ResponseMode.DirectPost,
//            responseUrl = "https://example.com/response",
//        )
//        val authnRequest = verifierOid4vp.createAuthnRequest(
//            requestOptions, OpenId4VpVerifier.CreationOptions.Query(walletUrl)
//        ).getOrThrow().url

        val authnRequest = """
            https://example.com/wallet/c8fa2833-1641-46d6-af0c-bc3e8b081eb4?response_type=vp_token&client_id=redirect_uri%3Ahttps%3A%2F%2Fexample.com%2Frp%2F7db83193-90f8-4c57-89b6-68c104e90067&state=bb86d345-89e8-418e-987f-84b366667989&nonce=01999506-7074-7baf-9602-ae175207cad6&client_metadata=%7B%22redirect_uris%22%3A%5B%22https%3A%2F%2Fexample.com%2Frp%2F7db83193-90f8-4c57-89b6-68c104e90067%22%5D%2C%22jwks%22%3A%7B%22keys%22%3A%5B%7B%22crv%22%3A%22P-256%22%2C%22kty%22%3A%22EC%22%2C%22x%22%3A%22KWllX3_REQ5p0P_joUN5VqmmOj6m0uYK3Qx5itY2SNs%22%2C%22y%22%3A%22cM2nUk2WS-Vu7mlD9l_azLwhhw3HqOW7n35SfSEY5Bw%22%7D%5D%7D%2C%22authorization_signed_response_alg%22%3A%22ES256%22%2C%22vp_formats%22%3A%7B%22jwt_vp%22%3A%7B%22alg%22%3A%5B%22ES256%22%5D%7D%2C%22vc%2Bsd-jwt%22%3A%7B%22sd-jwt_alg_values%22%3A%5B%22ES256%22%5D%2C%22kb-jwt_alg_values%22%3A%5B%22ES256%22%5D%7D%2C%22dc%2Bsd-jwt%22%3A%7B%22sd-jwt_alg_values%22%3A%5B%22ES256%22%5D%2C%22kb-jwt_alg_values%22%3A%5B%22ES256%22%5D%7D%2C%22mso_mdoc%22%3A%7B%22alg%22%3A%5B%22ES256%22%5D%7D%7D%2C%22client_id_scheme%22%3A%22pre-registered%22%7D&presentation_definition=%7B%22id%22%3A%2299989cc2-b09a-4860-90a1-c35e45093019%22%2C%22input_descriptors%22%3A%5B%7B%22id%22%3A%22org.iso.18013.5.1.mDL%22%2C%22format%22%3A%7B%22mso_mdoc%22%3A%7B%22alg%22%3A%5B%22ES256%22%5D%7D%7D%2C%22constraints%22%3A%7B%22fields%22%3A%5B%7B%22optional%22%3Afalse%2C%22path%22%3A%5B%22%24%5B%27org.iso.18013.5.1%27%5D%5B%27family_name%27%5D%22%5D%2C%22intent_to_retain%22%3Afalse%7D%5D%2C%22limit_disclosure%22%3A%22required%22%7D%7D%5D%7D&response_mode=direct_post&response_uri=https%3A%2F%2Fexample.com%2Fresponse
        """.trimIndent()
        val mapStore = FixedMapStore(
            RequestParser().parseRequestParameters(authnRequest).getOrThrow()
                .shouldBeInstanceOf<RequestParametersFrom<AuthenticationRequestParameters>>()
                .parameters
        )
        val verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            decryptionKeyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId),
            nonceService = FixedNonceService(),
            stateToAuthnRequestStore = mapStore
        )
//        variable input has been generated with this code:
//
//        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
//            .shouldBeInstanceOf<AuthenticationResponseResult.Post>()
//
//        val input = authnResponse.params.formUrlEncode()

        val requestedClaim = MobileDrivingLicenceDataElements.FAMILY_NAME
        val input = """
            vp_token=o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xgdgYWFmkaGRpZ2VzdElEAGZyYW5kb21QDb7z2zRTzqfbIzJXfVMUz3FlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZWxlbGVtZW50VmFsdWVqTXVzdGVybWFubmppc3N1ZXJBdXRohEOhASahGCFZARQwggEQMIG3oAMCAQICAQEwCgYIKoZIzj0EAwIwEjEQMA4GA1UEAwwHRGVmYXVsdDAeFw0yNTA5MjkxMDUwMTZaFw0yNTA5MjkxMDUwNDZaMBIxEDAOBgNVBAMMB0RlZmF1bHQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARIhrlkDOd96zvtpIxonDibGOjWOahIgmwQIMMzFSssuz6u6DqdD4HhROnVSQZAMPZzQ0TIi4vdE7gHWovE7PKJMAoGCCqGSM49BAMCA0gAMEUCIQDvpsHo-CjGDkMOvPN4EzT5kx3oHiRcr2WIq7KDh0nPrAIgXwqxcrPJJMeKaQNiiy0kLqSMFue1uAF1IcM6BLXUPjFZA1LYGFkDTadndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZsdmFsdWVEaWdlc3RzoXFvcmcuaXNvLjE4MDEzLjUuMawAWCBBdQE0VpBRTFIO0yquDJ-_jK_9KrHWQOBo3ng9jlu0MgFYIA9hQVvL9b0xVwPYgOzrAR7S2ZqRauzNgArK69QB5lAmAlggoxxNyZ_kcymyiTKRr9J4Vigu3L9XfHQ7YATg_0Z2U7sDWCCXVEJiC97qh-VtkLGMQsIooWvBeXH9rPDj627ICtAuBgRYIN7Pq3oqzhuEz5tKhkHA-ronnk1cfXf8UPmcQ07mRqEhBVggYUNiUGx0hGdHYe0ryCl3isdmtw_fa7VfPGh-SxtffoYGWCAlzsLeQX8c0NaLshKodYvV7ggbR2gIIbLzOntNovJ8qgdYIBtAzCI4CdSPMq4DcGYzNSEMOJveu7vGyunbdJ07j2IuCFggODBoHhkBw0bAm4IIRMZV4LkrPuBHU8gK_gxx-J8y990JWCDylmsMn6BpRvYJAARy1IJZd3enxX5jKy_XYr9RXLWfsQpYIDaFTkAxVVhigEy3n8BZ4uqh6g0ja2bu69RFv_Bl5V12C1ggM14pYhXoLB94hC21A0xLeej3QrsRbAoTbopwHJKnZcdtZGV2aWNlS2V5SW5mb6FpZGV2aWNlS2V5pAECIAEhWCDy7kQjFrFYfTMn_2Edw1m-uKHQNrHXJPhNElSPCfT_cSJYIECVhqkgkY8P9u-9QJHngGCIaCbSw1Myct3sHLw_wkwQZ2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHgeMjAyNS0wOS0yOVQxMDo1MDoxNi4zMzg5OTIwMThaaXZhbGlkRnJvbcB4HjIwMjUtMDktMjlUMTA6NTA6MTYuMzM4OTkyMDE4Wmp2YWxpZFVudGlswHgeMjAyNS0wOS0yOVQxMDo1MToxNi4zMzg4NzE4MjNaZnN0YXR1c6Frc3RhdHVzX2xpc3SiY2lkeAFjdXJpeDRodHRwczovL3dhbGxldC5hLXNpdC5hdC9iYWNrZW5kL2NyZWRlbnRpYWxzL3N0YXR1cy8xWEAZypUDQgH4BthAZYnMllkYQpUwNTumgPG7vG4co2HbOZu3tiX0OfHbapY4N_sFYMJjjhN7LzraSOFzuYb1aIwybGRldmljZVNpZ25lZKJqbmFtZVNwYWNlc9gYQaBqZGV2aWNlQXV0aKFvZGV2aWNlU2lnbmF0dXJlhEOhASag9lhAkdjhEdtzS0SM1Chg3tosW_mzlAPZwMXKkOYb1qo2MiSS1dlUhA0xdx_YbqBKjDTO56-pDKZo-Z-eJC4AZQqN-2ZzdGF0dXMA&presentation_submission=%7B%22id%22%3A%2274a00641-2c82-4f60-b8c9-d442eae588a2%22%2C%22definition_id%22%3A%2299989cc2-b09a-4860-90a1-c35e45093019%22%2C%22descriptor_map%22%3A%5B%7B%22id%22%3A%22org.iso.18013.5.1.mDL%22%2C%22format%22%3A%22mso_mdoc%22%2C%22path%22%3A%22%24%22%7D%5D%7D&state=bb86d345-89e8-418e-987f-84b366667989
        """.trimIndent()

        verifierOid4vp.validateAuthnResponse(input)
            .shouldBeInstanceOf<AuthnResponseResult.SuccessIso>()
            .documents.first().apply {
                validItems.shouldBeSingleton()
                validItems.shouldHaveSingleElement { it.elementIdentifier == requestedClaim }
                invalidItems.shouldBeEmpty()
            }
    }


    "Selective Disclosure with mDL and encryption (ISO/IEC 18013-7:2024 Annex B)" {
        val keyDerBase64 =
            "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCyUYuUliGjk9NuPnMwhfULYpnR4H4KWpdlyrdWHKf+ew=="
        val verifierKeyMaterial = FixedKeyMaterial(keyDerBase64.decodeToByteArray(Base64Strict))
        val clientId = "https://example.com/rp/b4531ae1-e9ea-41a2-a85c-965705885b6f"
        val requestedClaim = MobileDrivingLicenceDataElements.FAMILY_NAME

//        variable authnRequest has been generated with this code:
//
//        val requestOptions = RequestOptions(
//            credentials = setOf(
//                RequestOptionsCredential(
//                    MobileDrivingLicenceScheme,
//                    ConstantIndex.CredentialRepresentation.ISO_MDOC,
//                    setOf(requestedClaim)
//                )
//            ),
//            responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
//            responseUrl = "https://example.com/response",
//            encryption = true
//        )
//        val authnRequest = verifierOid4vp.createAuthnRequest(
//            requestOptions, OpenId4VpVerifier.CreationOptions.Query(walletUrl)
//        ).getOrThrow().url

        val authnRequest = """
            https://example.com/wallet/ae3462dc-861c-4f6f-a5d7-fb7ab881692a?response_type=vp_token&client_id=redirect_uri%3Ahttps%3A%2F%2Fexample.com%2Frp%2Fb4531ae1-e9ea-41a2-a85c-965705885b6f&state=15440b85-5a69-4fda-a299-0b5a5822f1e4&nonce=01999506-7074-7baf-9602-ae175207cad6&client_metadata=%7B%22redirect_uris%22%3A%5B%22https%3A%2F%2Fexample.com%2Frp%2Fb4531ae1-e9ea-41a2-a85c-965705885b6f%22%5D%2C%22jwks%22%3A%7B%22keys%22%3A%5B%7B%22crv%22%3A%22P-256%22%2C%22kty%22%3A%22EC%22%2C%22use%22%3A%22enc%22%2C%22x%22%3A%22oaCN5kbaeMt5SavygZMILPLMqDCcA-Q6iV8s-xRJ0qM%22%2C%22y%22%3A%22wNm-5tdda7UPqoHLYJmwHEbYbv2XxibtVmy6lRmebZo%22%7D%5D%7D%2C%22authorization_encrypted_response_alg%22%3A%22ECDH-ES%22%2C%22authorization_encrypted_response_enc%22%3A%22A256GCM%22%2C%22vp_formats%22%3A%7B%22jwt_vp%22%3A%7B%22alg%22%3A%5B%22ES256%22%5D%7D%2C%22vc%2Bsd-jwt%22%3A%7B%22sd-jwt_alg_values%22%3A%5B%22ES256%22%5D%2C%22kb-jwt_alg_values%22%3A%5B%22ES256%22%5D%7D%2C%22dc%2Bsd-jwt%22%3A%7B%22sd-jwt_alg_values%22%3A%5B%22ES256%22%5D%2C%22kb-jwt_alg_values%22%3A%5B%22ES256%22%5D%7D%2C%22mso_mdoc%22%3A%7B%22alg%22%3A%5B%22ES256%22%5D%7D%7D%2C%22client_id_scheme%22%3A%22pre-registered%22%7D&presentation_definition=%7B%22id%22%3A%223b71daa0-2144-48f0-8df4-4abf28fbdc18%22%2C%22input_descriptors%22%3A%5B%7B%22id%22%3A%22org.iso.18013.5.1.mDL%22%2C%22format%22%3A%7B%22mso_mdoc%22%3A%7B%22alg%22%3A%5B%22ES256%22%5D%7D%7D%2C%22constraints%22%3A%7B%22fields%22%3A%5B%7B%22optional%22%3Afalse%2C%22path%22%3A%5B%22%24%5B%27org.iso.18013.5.1%27%5D%5B%27family_name%27%5D%22%5D%2C%22intent_to_retain%22%3Afalse%7D%5D%2C%22limit_disclosure%22%3A%22required%22%7D%7D%5D%7D&response_mode=direct_post.jwt&response_uri=https%3A%2F%2Fexample.com%2Fresponse
        """.trimIndent()
        val mapStore = FixedMapStore(
            RequestParser().parseRequestParameters(authnRequest).getOrThrow()
                .shouldBeInstanceOf<RequestParametersFrom<AuthenticationRequestParameters>>()
                .parameters
        )
        val verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            decryptionKeyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId),
            nonceService = FixedNonceService(),
            stateToAuthnRequestStore = mapStore
        )

//        variable input has been generated with this code:
//
//        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
//            .shouldBeInstanceOf<AuthenticationResponseResult.Post>()
//        val input = authnResponse.params.formUrlEncode()

        val input = """
            response=eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImp3ayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImhaWGNqZlZrUE13U3c5ZEl5YXRvbjgtN09leWRFbjlaX3pIbFZnV1hPVjQiLCJ5IjoiY1lVTDl5eEdwTUR0OWo4NWJGZWYxeFpERWpTNlloUlZBaEk5ME90SjlSMCJ9LCJlcGsiOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiI3NVBJYnVuT2l4c1JaVy1JLTNqamZIV1puTVdUb2Z2WUJVeWFOZ1hxLXNjIiwieSI6IkZzVTJaSF8tVEZWTlM1c1gtLUMxNnlJSXlGa25oQkJmS0o1LUk1QUNfWTgifSwiYXB1IjoiU1ZKQlJtWkZRMkZ2UlRJNVFYZDBhRXhuTkVSWFFRIiwiYXB2IjoiTURFNU9UazFNRFl0TnpBM05DMDNZbUZtTFRrMk1ESXRZV1V4TnpVeU1EZGpZV1EyIn0..S1K4_3kjvYNh9ijT.F2VoUAQwEWBSizUOBhizt8bJ5cdJlxJAwrF8xnMtuhtUnPWF1X2f43lTruM708uUVaC7Y_igHPDAoE50M3ldxA8WslwMARlX4NB17SoDvHS5ig1XgMuikUJj5N9lPHvvmN8e8kHUN3cTunMAUlibBPGpZ9SDD9cqvNWBa9SUzFBqH7WyPPE2QYFMGiUShGgNLFHCcNv2o0VkHKEcgsXqhh0vynAJ4K6ygqkRAzCjtoMZY4Ekfa8O9T2woMKrrnbwnCq-L2vJwg8DPmqTcWfB8Q1_T2u2m-Z7sLa9ABaqhHmDLCV0zGhKdlqKUbk_dVhEzI13t69C-YRzsIBDved7X6tL6ZSHiSTMtmRNTwFMnyaz-Ty4OZwY6WMJxROV4XzyXWlDQZtbPdnI8eiHfGq-uqppe8Mzkz5euoEMkyFpxIAevC-TCxFvsqDsfA_A2dGRccb1FOwAHA_uzUHmEXrv6N-PJqfAr_OYUhF_XAlY1-OnPrfTowwklq_3EpTzCYCOpTNb39LwATj6Ud0BZr6FUptl777miTgaQIOjXXaaMcQ4lNRQv9ZB1pkyva6lteejoAuq2Q2t6ggf3d8fln0aknMf1uthBH0LiYAwQN4DdEZ7bm8HHlRfBHYYX3mknqrqaydzgsd8rB7yX2RaAXqLR8V93BadXaH4mOZCEbta9_2K8kw-9B-tkmP825OEI1ZDr7Gu-5PplU22ihKUtPa3NDudCEAAdv5vyaLbG1ssxgV25Ftx1ARz5eK5DPVZk-Jy_bLiPp0ZNbZWDlHyuRWJQvzRvAyCPXt9YLfI1R6Ty56vB8WCa9IWkjslyVGcnFlri8SLaM3U6Azomkt9H43W3HPRjp_WjImU_rUSjJSE-1PENcYvJ1NU6gSphNEWQun4HfZFY4eZrODJgo3ho2FI_sa8pQJ7laOvKPVMyT4GcW-UcyKG-V21hU0CFrxLYXfknhwMRQ0qVHFxlHh-kpQdXhVRBZ0FKWcguFxBCVgmPqxxcdgXp79klpvAg18YRxSxrsLBqQpXzVKPb6CJffRTNv4OuOXTuZVw-EoJ6f2U0zcIsQDTLToTPlAlOLvE9bO8Q5LsHO2SkFfXDcKVZ3m7FQglWRMMd3kmKhi9KoRZxHyUrOVKlb2Cft73IFgklAVEAFXC9Bg9zELeAbdQ7Gk5q1ZxQy8JJoxal3An48AfNlF2djd01GpeFmmmWQerF26bbsYFHiNM4YmMw1NNPTN0jZN4xsBqOtL6_YDEvBF76qmncT9NObxB1oQJ8YWmIp0Y-qNe62DPY37zFAMI8FzzulSvxcO1jeIiqosOCxst7__EYH-tG3kOgc3Zk7ibeqliC0ZTscEzW64Wt6YVr7W9vpXgyAhrteWX9Ln2Sq0931t8P64L-i-WQsbDgltrapXnnLVmHDzoYPbVKsBrEoneJNfUthbREETCoKqyWmLUy082YYDE92K4yDy756zwyYaYnHiayF0a-FBEn4x0LawkurzKmRKzexJjWTgMhycBF9GGntdfHAVofYXg-x1zTuSCaqU9qsZa2QG5km4G1BjTE3wTJ5drgSqtAGQ2E-Z0cRCwrdPwIath2EjRdUr4Z8m57mBSsZ3OsnjqIxHPhHt1e2NaOpIobwP0hRM34mwyNOWVqf2bYoUV_RYcUHzzRW6GLBd7-G9t8HVvxICbhNgJwXjFCxaVxEZETmMYIx3qzXTmZCHSpGrKI8rFCXwlrZJggeOO21qGPU3wl9axVVdKSEjN8rtJlCqzR156DY2AswnC_TjkeUizjvf7GB2rByitrKO-CqovUhUE1Jl8CXgX2kqCZquWAR17lBEL-rbRnmfUWXeOQrwbBYshhNt6qD23S74aaAzN7XAbn3QM7nR90sP4PlFXQYIkYerjUzKJMlpUO0IBPc_P2cHsj9NZ3S1-bDpbnfy_WfO-UYrvXiqsNZVauTeldhbSErb3mhgV97lCax8Asb44xhQnorYbJNNUGw0Fa35juD-ICE_zgMqszuOZ5iftyLLdgWytJUhnmK-QjialmMEGLOhEpn020JbIb6fqm7I_NBiQJHCTH2AJDhsxgMJUWdN0cRbp9fz3ZWENVumkxAJpO3HApbBztUAlASF45GqaY_BttXsNW_GUCWR4LI74cTdpOzKQD8Nib6Ev2xOdiLr0WEhiibQY8qQ5UyJ_Vsir5F3jsN-NNnGay03OEcu4vvICW7S_7IytiU1GL1WjH9eINWq5vJZg3TMhHLc5haKbazFR1BTQQHHjeO-lSatJMNvAEO_EPRjyLvqnaEJ8z5zDltlIlvX3g8MSlEix_6Ocvl9M8pbr0fS8IFtK-Fa_Tg2vNGJOY_XDhXuZ1407fd83uchLgcxSY5PcuzDy2z0NEBo4rzx4_2uV9SYmZ9cXQGLK5NUAysY-7-4nQL8ygV0Sbqp1qNSwrdkYBfBdi_FsKhpvHB8F4Hp3B9QTH9b9fqiy8-v_D_QnFkEIj0namxCbVRHMgsVTNpyKWUTEUvVSop82LruWVfoluGTBGrgL5Cnu0yd6IiooDFPbJxddpcWrpiR9AsYvZrSrxFdU-pjAW8FHa3mHkNdIOTPVRpklGpzOivZijIQBqHuYYYGFUIFNHRvqCHFdtzJcIMxPtMW8NFjmNwl2xF5LnxFncIfQpuj8eqh2Us1YU8WIRo96Skn6lxG8c7gWVZs273rAXb1iLo21Y0qgfHyCeYpVCZiVzNA_GfKEnC4J6EWxLLRFm3oEbxi3iUH6OG9eC3aaT-E22a6mqEFTwJv-uAqR4-IwAgr1xBoicsr1unvzObBKAPz1xTQiQJjvOaOCh1hSHuOXiT06a0JKofkOXRdagkaEB1I8zOHLqJ6___MKeh61ohA-uxXBshySTWruqsQZ5B_f4xweGESvRiMQRVsdV87f-lx6T7pZYT0Zpzil1l58PbGzPuXxoMa_7tpLTR3c5hPkSUqlVTfR4kXZeth-To7JukWHrCpDZzgjSPSeROeo81AVsdQg31tgk6-hsixtA9WIH5cYIhr4Its_FUhc1LuTyELr74G_TSel5LVCe2H7muUZQZJyEWntnkYpNcEqHzO4HTH1zKvIbNeSlGUfNNaQwsieQG-ddIE_.ck1KMnYLZMZvWtioaxub2g
        """.trimIndent()

        verifierOid4vp.validateAuthnResponse(input).also {
            if (it is AuthnResponseResult.Error) it.cause?.printStackTrace()
        }.shouldBeInstanceOf<AuthnResponseResult.SuccessIso>()
            .documents.first().apply {
                validItems.shouldBeSingleton()
                validItems.shouldHaveSingleElement { it.elementIdentifier == requestedClaim }
                invalidItems.shouldBeEmpty()
            }
    }
}

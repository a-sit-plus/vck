package at.asitplus.dcapi.request.verifier

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

internal const val DIGITAL_CREDENTIAL_REQUEST_OPTIONS_JSON =
    """{"requests":[{"data":{"request":"eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRVMyNTYiLCJ4NWMiOlsiTUlJQ2NEQ0NBaFdnQXdJQkFnSVVWZjB0a080c1J1U2ZWazE3NFlZQmxORDdQSW93Q2dZSUtvWkl6ajBFQXdJd0xqRUxNQWtHQTFVRUJoTUNRVlF4RGpBTUJnTlZCQW9NQlVFdFUwbFVNUTh3RFFZRFZRUUREQVpFWlhZZ1EwRXdIaGNOTWpVd01qQTBNVEkwTVRVeldoY05Nall3TWpBME1USTBNVFV6V2pBMU1Rc3dDUVlEVlFRR0V3SkJWREVOTUFzR0ExVUVDZ3dFUlVkSldqRVhNQlVHQTFVRUF3d09RM1Z6ZEc5dGRtVnlhV1pwWlhJd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFSaDFLclo4VTlkbjNhWUNWcUVwRVo1dmN4b3ljOEFzdFZOTENvWVViYjV3OVVxSmdLQlpmMjRvMktrNmtzU3dBeHVVS1JZZ2N3d1h3N2ZBYkVRNTN2dG80SUJDRENDQVFRd0RnWURWUjBQQVFIL0JBUURBZ1dnTUlHY0JnTlZIUkVFZ1pRd2daR0NEMkZ3Y0hNdVpXZHBlaTVuZGk1aGRJSU9RM1Z6ZEc5dGRtVnlhV1pwWlhLQ0NXeHZZMkZzYUc5emRJSVBkMkZzYkdWMExtRXRjMmwwTG1GMGdoeDROVEE1WDNOaGJsOWtibk02WVhCd2N5NWxaMmw2TG1kMkxtRjBnaFo0TlRBNVgzTmhibDlrYm5NNmJHOWpZV3hvYjNOMGdoeDROVEE1WDNOaGJsOWtibk02ZDJGc2JHVjBMbUV0YzJsMExtRjBNQjhHQTFVZEl3UVlNQmFBRkdPWlpCbTVJRTZxanRRcUsrQXJwNWk1NDdBUU1CMEdBMVVkRGdRV0JCUW51MksxVE9kc0Y4WnFQQk9LSnV4NjZHanE4REFUQmdOVkhTVUVEREFLQmdnckJnRUZCUWNEQVRBS0JnZ3Foa2pPUFFRREFnTkpBREJHQWlFQW9JUC9tK3c0Q1ZXQmV3Q29IRDJtUU0xcWxHZm9iWk1GS0xXUHlFc3VOZzRDSVFDV3NBSmdJak9wcHhWOVE3ZGlQN0VTd1dSYlpIUlA1MWYwUFRJY2xpaW5sQT09Il19.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ4NTA5X3Nhbl9kbnM6bG9jYWxob3N0IiwicmVkaXJlY3RfdXJpIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwLyIsIm5vbmNlIjoiZjIwYWJiMGUtMmYwZC00ZTdiLTlmYjAtYmY3MWQ0ZTVhMWI5IiwiY2xpZW50X21ldGFkYXRhIjp7InJlZGlyZWN0X3VyaXMiOltdLCJqd2tzIjp7ImtleXMiOlt7ImFsZyI6IkVDREgtRVMiLCJjcnYiOiJQLTI1NiIsImtpZCI6IjExMDAzMzg4ZTE3ZTRmYzIiLCJrdHkiOiJFQyIsIngiOiJldjZKcVJNcm1KLTlFV0toVXhhOEpGVXRGUWtzQkg0bEY0djdMcWVtZThvIiwieSI6Ild0c0U5QTVtbk5Yc0JCSDBFVUNzSmRhT0tmRzVaYWphS2hIQTl6alh1THcifV19LCJ2cF9mb3JtYXRzX3N1cHBvcnRlZCI6eyJqd3RfdmNfanNvbiI6eyJhbGdfdmFsdWVzIjpbIkVTMjU2Il19LCJkYytzZC1qd3QiOnsic2Qtand0X2FsZ192YWx1ZXMiOlsiRVMyNTYiXSwia2Itand0X2FsZ192YWx1ZXMiOlsiRVMyNTYiXX0sIm1zb19tZG9jIjp7Imlzc3VlcmF1dGhfYWxnX3ZhbHVlcyI6Wy03XSwiZGV2aWNlYXV0aF9hbGdfdmFsdWVzIjpbLTddfX19LCJkY3FsX3F1ZXJ5Ijp7ImNyZWRlbnRpYWxzIjpbeyJpZCI6ImRjM2MwYTI2LWI3OWUtNDc5Mi04NjgzLTcxYmM5ZDZkMzAxMCIsImZvcm1hdCI6Im1zb19tZG9jIiwibWV0YSI6eyJkb2N0eXBlX3ZhbHVlIjoib3JnLmlzby4xODAxMy41LjEubURMIn0sImNsYWltcyI6W3sicGF0aCI6WyJvcmcuaXNvLjE4MDEzLjUuMSIsImZhbWlseV9uYW1lIl0sIm5hbWVzcGFjZSI6Im9yZy5pc28uMTgwMTMuNS4xIiwiY2xhaW1fbmFtZSI6ImZhbWlseV9uYW1lIn0seyJwYXRoIjpbIm9yZy5pc28uMTgwMTMuNS4xIiwiZ2l2ZW5fbmFtZSJdLCJuYW1lc3BhY2UiOiJvcmcuaXNvLjE4MDEzLjUuMSIsImNsYWltX25hbWUiOiJnaXZlbl9uYW1lIn0seyJwYXRoIjpbIm9yZy5pc28uMTgwMTMuNS4xIiwiYmlydGhfZGF0ZSJdLCJuYW1lc3BhY2UiOiJvcmcuaXNvLjE4MDEzLjUuMSIsImNsYWltX25hbWUiOiJiaXJ0aF9kYXRlIn0seyJwYXRoIjpbIm9yZy5pc28uMTgwMTMuNS4xIiwiaXNzdWVfZGF0ZSJdLCJuYW1lc3BhY2UiOiJvcmcuaXNvLjE4MDEzLjUuMSIsImNsYWltX25hbWUiOiJpc3N1ZV9kYXRlIn0seyJwYXRoIjpbIm9yZy5pc28uMTgwMTMuNS4xIiwiZXhwaXJ5X2RhdGUiXSwibmFtZXNwYWNlIjoib3JnLmlzby4xODAxMy41LjEiLCJjbGFpbV9uYW1lIjoiZXhwaXJ5X2RhdGUifSx7InBhdGgiOlsib3JnLmlzby4xODAxMy41LjEiLCJpc3N1aW5nX2NvdW50cnkiXSwibmFtZXNwYWNlIjoib3JnLmlzby4xODAxMy41LjEiLCJjbGFpbV9uYW1lIjoiaXNzdWluZ19jb3VudHJ5In0seyJwYXRoIjpbIm9yZy5pc28uMTgwMTMuNS4xIiwiaXNzdWluZ19hdXRob3JpdHkiXSwibmFtZXNwYWNlIjoib3JnLmlzby4xODAxMy41LjEiLCJjbGFpbV9uYW1lIjoiaXNzdWluZ19hdXRob3JpdHkifSx7InBhdGgiOlsib3JnLmlzby4xODAxMy41LjEiLCJkb2N1bWVudF9udW1iZXIiXSwibmFtZXNwYWNlIjoib3JnLmlzby4xODAxMy41LjEiLCJjbGFpbV9uYW1lIjoiZG9jdW1lbnRfbnVtYmVyIn0seyJwYXRoIjpbIm9yZy5pc28uMTgwMTMuNS4xIiwicG9ydHJhaXQiXSwibmFtZXNwYWNlIjoib3JnLmlzby4xODAxMy41LjEiLCJjbGFpbV9uYW1lIjoicG9ydHJhaXQifSx7InBhdGgiOlsib3JnLmlzby4xODAxMy41LjEiLCJkcml2aW5nX3ByaXZpbGVnZXMiXSwibmFtZXNwYWNlIjoib3JnLmlzby4xODAxMy41LjEiLCJjbGFpbV9uYW1lIjoiZHJpdmluZ19wcml2aWxlZ2VzIn0seyJwYXRoIjpbIm9yZy5pc28uMTgwMTMuNS4xIiwidW5fZGlzdGluZ3Vpc2hpbmdfc2lnbiJdLCJuYW1lc3BhY2UiOiJvcmcuaXNvLjE4MDEzLjUuMSIsImNsYWltX25hbWUiOiJ1bl9kaXN0aW5ndWlzaGluZ19zaWduIn1dfV19LCJyZXNwb25zZV9tb2RlIjoiZGNfYXBpIiwicmVzcG9uc2VfdXJpIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3RyYW5zYWN0aW9uL3Jlc3VsdC9mY2JlMDVjMS0xODQ3LTQ2MGEtOWE3NC02N2Q3OGM3YmZkZGEiLCJhdWQiOiJodHRwczovL3NlbGYtaXNzdWVkLm1lL3YyIiwiaXNzIjoiaHR0cHM6Ly9zZWxmLWlzc3VlZC5tZS92MiIsImV4cGVjdGVkX29yaWdpbnMiOlsiaHR0cDovL2xvY2FsaG9zdDo4MDgwLyJdfQ.ZNiDNKIZyrjvLIpH7T5nOmrpxVl7WF-bspkx95PtRxFZmxaRJ50oKjl8F7ynFe_7b4EOawnsjALKYHkx7_4fAg"},"protocol":"openid4vp-v1-signed"},{"data":{"deviceRequest":"omd2ZXJzaW9uYzEuMGtkb2NSZXF1ZXN0c4GhbGl0ZW1zUmVxdWVzdNgYWOeiZ2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xq2tmYW1pbHlfbmFtZfRqZ2l2ZW5fbmFtZfRqYmlydGhfZGF0ZfRqaXNzdWVfZGF0ZfRrZXhwaXJ5X2RhdGX0b2lzc3VpbmdfY291bnRyefRxaXNzdWluZ19hdXRob3JpdHn0b2RvY3VtZW50X251bWJlcvRocG9ydHJhaXT0cmRyaXZpbmdfcHJpdmlsZWdlc_R2dW5fZGlzdGluZ3Vpc2hpbmdfc2lnbvQ","encryptionInfo":"gmVkY2FwaaJlbm9uY2VYJDc4YmMyYzMwLWM0NmEtNDI5ZC05OTI0LTE5N2ZmYWRlZTIxZnJyZWNpcGllbnRQdWJsaWNLZXmkAQIgASFYICRu-2zr9PXkqIvTwaYuUh_ha8i8GGySUnSjVXuqRE9QIlggQyHSG3UsODXw6h-IjJgEZI7ws8E1B9HbPcUxeye2Hjk"},"protocol":"org-iso-mdoc"}]}"""

internal const val DIGITAL_CREDENTIAL_REQUEST_OPTIONS_UNSIGNED_JSON =
    """{"requests":[{"data":{"client_metadata":{"jwks":{"keys":{"0":{"alg":"ECDH-ES","crv":"P-256","kid":"11003388e17e4fc2","kty":"EC","x":"ev6JqRMrmJ-9EWKhUxa8JFUtFQksBH4lF4v7Lqeme8o","y":"WtsE9A5mnNXsBBH0EUCsJdaOKfG5ZajaKhHA9zjXuLw"}}},"redirect_uris":{},"vp_formats_supported":{"dc+sd-jwt":{"kb-jwt_alg_values":{"0":"ES256"},"sd-jwt_alg_values":{"0":"ES256"}},"jwt_vc_json":{"alg_values":{"0":"ES256"}},"mso_mdoc":{"deviceauth_alg_values":{"0":-7},"issuerauth_alg_values":{"0":-7}}}},"dcql_query":{"credentials":{"0":{"claims":{"0":{"claim_name":"family_name","namespace":"org.iso.18013.5.1","path":{"0":"org.iso.18013.5.1","1":"family_name"}},"1":{"claim_name":"given_name","namespace":"org.iso.18013.5.1","path":{"0":"org.iso.18013.5.1","1":"given_name"}},"10":{"claim_name":"un_distinguishing_sign","namespace":"org.iso.18013.5.1","path":{"0":"org.iso.18013.5.1","1":"un_distinguishing_sign"}},"2":{"claim_name":"birth_date","namespace":"org.iso.18013.5.1","path":{"0":"org.iso.18013.5.1","1":"birth_date"}},"3":{"claim_name":"issue_date","namespace":"org.iso.18013.5.1","path":{"0":"org.iso.18013.5.1","1":"issue_date"}},"4":{"claim_name":"expiry_date","namespace":"org.iso.18013.5.1","path":{"0":"org.iso.18013.5.1","1":"expiry_date"}},"5":{"claim_name":"issuing_country","namespace":"org.iso.18013.5.1","path":{"0":"org.iso.18013.5.1","1":"issuing_country"}},"6":{"claim_name":"issuing_authority","namespace":"org.iso.18013.5.1","path":{"0":"org.iso.18013.5.1","1":"issuing_authority"}},"7":{"claim_name":"document_number","namespace":"org.iso.18013.5.1","path":{"0":"org.iso.18013.5.1","1":"document_number"}},"8":{"claim_name":"portrait","namespace":"org.iso.18013.5.1","path":{"0":"org.iso.18013.5.1","1":"portrait"}},"9":{"claim_name":"driving_privileges","namespace":"org.iso.18013.5.1","path":{"0":"org.iso.18013.5.1","1":"driving_privileges"}}},"format":"mso_mdoc","id":"020b1c01-cab9-4c1a-a740-faa3ad82afdf","meta":{"doctype_value":"org.iso.18013.5.1.mDL"}}}},"expected_origins":{"0":"http://localhost:8080/"},"nonce":"2c434631-9b41-47bd-b3a5-9f80f67f21a6","redirect_uri":"http://localhost:8080/","response_mode":"dc_api","response_type":"vp_token","response_uri":"http://localhost:8080/transaction/result/211f5535-8e56-4b98-9850-d9bf3ff33b59"},"protocol":"openid4vp-v1-unsigned"}]}"""

internal val testDigitalCredentialRequestOptions: DigitalCredentialRequestOptions by lazy {
    joseCompliantSerializer.decodeFromString(DIGITAL_CREDENTIAL_REQUEST_OPTIONS_JSON)
}

internal val testSignedOpenId4VpRequest: DigitalCredentialGetRequest.OpenId4VpSigned by lazy {
    testDigitalCredentialRequestOptions.requests
        .filterIsInstance<DigitalCredentialGetRequest.OpenId4VpSigned>()
        .first()
}

internal val testIsoMdocRequest: DigitalCredentialGetRequest.IsoMdoc by lazy {
    testDigitalCredentialRequestOptions.requests
        .filterIsInstance<DigitalCredentialGetRequest.IsoMdoc>()
        .first()
}

internal val testUnsignedOpenId4VpRequest: DigitalCredentialGetRequest.OpenId4VpUnsigned by lazy {
    val normalized = normalizeIndexedObjectsToArrays(
        Json.parseToJsonElement(DIGITAL_CREDENTIAL_REQUEST_OPTIONS_UNSIGNED_JSON)
    )
    joseCompliantSerializer.decodeFromJsonElement(DigitalCredentialRequestOptions.serializer(), normalized).requests
        .filterIsInstance<DigitalCredentialGetRequest.OpenId4VpUnsigned>()
        .first()
}

private fun normalizeIndexedObjectsToArrays(element: JsonElement): JsonElement =
    when (element) {
        is JsonObject -> {
            val normalized = element.mapValues { (_, value) -> normalizeIndexedObjectsToArrays(value) }
            val normalizedObject = JsonObject(normalized)
            val keys = normalizedObject.keys
            if (keys.isEmpty()) {
                JsonArray(emptyList())
            } else if (keys.all { it.toIntOrNull() != null }) {
                val indices = keys.map { it.toInt() }.sorted()
                if (indices == (0 until indices.size).toList()) {
                    JsonArray(indices.map { index -> normalizedObject[index.toString()]!! })
                } else {
                    normalizedObject
                }
            } else {
                normalizedObject
            }
        }
        is JsonArray -> JsonArray(element.map { normalizeIndexedObjectsToArrays(it) })
        else -> element
    }

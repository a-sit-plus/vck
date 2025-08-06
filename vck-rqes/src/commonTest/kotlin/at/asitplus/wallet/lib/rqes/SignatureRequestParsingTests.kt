package at.asitplus.wallet.lib.rqes

import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.qes.SignatureRequestParameters
import at.asitplus.wallet.lib.openid.RequestParser
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.types.shouldBeInstanceOf

class SignatureRequestParsingTests : FreeSpec({
    val jwt =
        """eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDpkcl9wb2M6c2lnIzEiLCJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0In0.eyJyZXNwb25zZV90eXBlIjoic2lnbl9yZXF1ZXN0IiwiY2xpZW50X2lkIjoiaHR0cHM6Ly9hcHBzLmVnaXouZ3YuYXQvZHJpdmluZ2FwcCIsImNsaWVudF9pZF9zY2hlbWUiOiJyZWRpcmVjdF91cmkiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV91cmkiOiJodHRwczovL2FwcHMuZWdpei5ndi5hdC9kcml2aW5nYXBwL3dhbGxldC9zaWduUmVzcG9uc2UiLCJub25jZSI6ImQ5NWMwOGM4LTNhYmUtNDc5ZS05YzM1LTg3YmYyMTk2NzdhZCIsInN0YXRlIjoiMDFmY2EwMTEtZmU0Yi00NDQ2LTlmYWQtMDVhNTkwZjMzMTZlIiwic2lnbmF0dXJlUXVhbGlmaWVyIjoiZXVfZWlkYXNfcWVzIiwiZG9jdW1lbnREaWdlc3RzIjpbeyJoYXNoIjoiaGJlREZZUUowODNrMXJQb3JsM0hYeVJ3WkM0VG9LZUlVN2thR0dJYkUwWT0iLCJsYWJlbCI6InRlc3QudHh0In1dLCJkb2N1bWVudExvY2F0aW9ucyI6W3sidXJpIjoiaHR0cHM6Ly9hcHBzLmVnaXouZ3YuYXQvZHJpdmluZ2FwcC9kb2MvY2FsbGJhY2s_dXVpZD0zMDliNzg5ZS0xZTNlLTRjNzMtYmNhNi0zMzIyY2U0YjgxMTQiLCJtZXRob2QiOnsidHlwZSI6InB1YmxpYyIsIm9uZVRpbWVQYXNzd29yZDoiOm51bGx9fV0sImhhc2hBbGdvcml0aG1PSUQiOiIyLjE2Ljg0MC4xLjEwMS4zLjQuMi4xIiwiY2xpZW50RGF0YSI6bnVsbH0.FgD4CT_x-uzbOLMxqwuNB9dr8v6OieCgGsQJFlEUy0QUHnAITFkbQKm8p-mEqYgDClkUOnqih0q9j8ou-9V88ugU3c1BL3ZSilf2hLlmkfnEA3D1YPv3fsKDsGpd_DF1pWOZoKF4h10aUsF65076NycPBUn5xGBMLBaMUonVUcNzsZ_4e-MQZbQIqDybwr_d7giv0IU-HZzUIMfFB7aYwST8WMeB264Hl3T53nNr3o6zNQD5el-IfOYrRgz-gOwRkR9ewOquTkcFu1BPWSwH_BenEUlgECrf9Di2bGAcLrC4DLIc79dyPGKi3WZO4HAoZWIdN5wEeSf6Ke4Ua0GUFiZlu_a1wtAs5ZL6iClkxS91kB3E59yOH6lf41EGxI2TE7M3giGBswJS9vIeU6mQDmy42pkNS6PE5VUIau0wJcyu_ChK-Ms6svEQgQ_hC4aKYiYBf4rnRLW8hirG-hSH91qvkqmS89STalIfl1eZtxThhmhxhldNkqUuDGlgTyFv"""
    val parser = RequestParser()

    "can parse SignatureRequestParameter from signed JWT" {
        val res = parser.parseRequestParameters(jwt).getOrThrow()
        res.shouldBeInstanceOf<RequestParametersFrom.JwsSigned<SignatureRequestParameters>>()
        res.parameters.documentDigests.shouldNotBeEmpty()
        res.parameters.documentLocations.shouldNotBeEmpty()
    }

    "can parse SignatureRequestParameter without clientData" {
        val input = """{
              "response_type": "sign_response",
              "client_id": "ff008dbe-0a00-43aa-8cbd-57b44fbd8cf9",
              "response_mode": "direct_post",
              "response_uri": "https://walletcentric.signer.eudiw.dev/rp/wallet/sd/upload/ff008dbe-0a00-43aa-8cbd-57b44fbd8cf9",
              "nonce": "SD6caM6K17zn6lnvVlu9FQ92Je2rWg-rqbMegL1CBIY",
              "signatureQualifier": "eu_eidas_qes",
              "documentDigests": [
                {
                  "hash": "dbe822af4b1cfddea8e8526a04a46557074d093cb02fee0f3dcc5f323629504e",
                  "label": "sample.pdf"
                }
              ],
              "documentLocations": [
                {
                  "uri": "https://walletcentric.signer.eudiw.dev/rp/tester/document/sample.pdf",
                  "method": {
                    "type": "public"
                  }
                }
              ],
              "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
            }""".replace("\n", "").replace("\r", "").trimIndent()
        val res = parser.parseRequestParameters(input).getOrThrow()
        res.shouldBeInstanceOf<RequestParametersFrom.Json<SignatureRequestParameters>>()
    }
})
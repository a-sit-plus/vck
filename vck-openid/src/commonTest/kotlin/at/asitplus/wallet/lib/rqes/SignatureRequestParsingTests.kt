package at.asitplus.wallet.lib.rqes

import at.asitplus.wallet.lib.oidc.SignatureRequestParametersFrom
import at.asitplus.wallet.lib.oidc.helper.RequestParser
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

class SignatureRequestParsingTests : FreeSpec({
    //TODO better tests
    val jwt =
        """eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDpkcl9wb2M6c2lnIzEiLCJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0In0.eyJyZXNwb25zZV90eXBlIjoic2lnbl9yZXF1ZXN0IiwiY2xpZW50X2lkIjoiaHR0cHM6Ly9hcHBzLmVnaXouZ3YuYXQvZHJpdmluZ2FwcCIsImNsaWVudF9pZF9zY2hlbWUiOiJyZWRpcmVjdF91cmkiLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV91cmkiOiJodHRwczovL2FwcHMuZWdpei5ndi5hdC9kcml2aW5nYXBwL3dhbGxldC9zaWduUmVzcG9uc2UiLCJub25jZSI6ImQ5NWMwOGM4LTNhYmUtNDc5ZS05YzM1LTg3YmYyMTk2NzdhZCIsInN0YXRlIjoiMDFmY2EwMTEtZmU0Yi00NDQ2LTlmYWQtMDVhNTkwZjMzMTZlIiwic2lnbmF0dXJlUXVhbGlmaWVyIjoiZXVfZWlkYXNfcWVzIiwiZG9jdW1lbnREaWdlc3RzIjpbeyJoYXNoIjoiaGJlREZZUUowODNrMXJQb3JsM0hYeVJ3WkM0VG9LZUlVN2thR0dJYkUwWT0iLCJsYWJlbCI6InRlc3QudHh0In1dLCJkb2N1bWVudExvY2F0aW9ucyI6W3sidXJpIjoiaHR0cHM6Ly9hcHBzLmVnaXouZ3YuYXQvZHJpdmluZ2FwcC9kb2MvY2FsbGJhY2s_dXVpZD0zMDliNzg5ZS0xZTNlLTRjNzMtYmNhNi0zMzIyY2U0YjgxMTQiLCJtZXRob2QiOnsidHlwZSI6InB1YmxpYyIsIm9uZVRpbWVQYXNzd29yZDoiOm51bGx9fV0sImhhc2hBbGdvcml0aG1PSUQiOiIyLjE2Ljg0MC4xLjEwMS4zLjQuMi4xIiwiY2xpZW50RGF0YSI6bnVsbH0.FgD4CT_x-uzbOLMxqwuNB9dr8v6OieCgGsQJFlEUy0QUHnAITFkbQKm8p-mEqYgDClkUOnqih0q9j8ou-9V88ugU3c1BL3ZSilf2hLlmkfnEA3D1YPv3fsKDsGpd_DF1pWOZoKF4h10aUsF65076NycPBUn5xGBMLBaMUonVUcNzsZ_4e-MQZbQIqDybwr_d7giv0IU-HZzUIMfFB7aYwST8WMeB264Hl3T53nNr3o6zNQD5el-IfOYrRgz-gOwRkR9ewOquTkcFu1BPWSwH_BenEUlgECrf9Di2bGAcLrC4DLIc79dyPGKi3WZO4HAoZWIdN5wEeSf6Ke4Ua0GUFiZlu_a1wtAs5ZL6iClkxS91kB3E59yOH6lf41EGxI2TE7M3giGBswJS9vIeU6mQDmy42pkNS6PE5VUIau0wJcyu_ChK-Ms6svEQgQ_hC4aKYiYBf4rnRLW8hirG-hSH91qvkqmS89STalIfl1eZtxThhmhxhldNkqUuDGlgTyFv"""

    "can parse SignatureRequestParameter from signed JWT" {
        val parser = RequestParser.createWithDefaults()
        val res = parser.parseRequestParameters(jwt).getOrThrow()
        res::class shouldBe SignatureRequestParametersFrom.JwsSigned::class
    }
})
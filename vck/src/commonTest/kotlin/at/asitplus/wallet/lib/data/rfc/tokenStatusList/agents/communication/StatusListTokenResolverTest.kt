@file:OptIn(ExperimentalStdlibApi::class)

package at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.MediaTypes
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication.primitives.StatusListTokenMediaType
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.data.rfc9110.HttpFieldLine
import at.asitplus.wallet.lib.data.rfc9110.HttpFieldName
import at.asitplus.wallet.lib.data.rfc9110.HttpFieldValue
import at.asitplus.wallet.lib.data.rfc9110.HttpRequestResolver
import at.asitplus.wallet.lib.data.rfc9110.HttpRequestTarget
import at.asitplus.wallet.lib.data.rfc9110.HttpResponseMessage
import at.asitplus.wallet.lib.data.rfc9110.HttpResponseMessageControlData
import at.asitplus.wallet.lib.data.rfc9110.HttpStatusCode
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import kotlinx.serialization.ExperimentalSerializationApi

@ExperimentalSerializationApi
class StatusListTokenResolverTest : FreeSpec({
    "from examples" - {
        val httpResolver = HttpRequestResolver {
            when (it.controlData?.requestTarget) {
                HttpRequestTarget("https://www.example.com/jwt") -> {
                    HttpResponseMessage(
                        controlData = HttpResponseMessageControlData(
                            statusCode = HttpStatusCode.OK,
                        ),
                        headers = listOf(
                            HttpFieldLine(
                                HttpFieldName.ContentType,
                                HttpFieldValue(MediaTypes.jwtStatusList),
                            )
                        ),
                        content = """eyJhbGciOiJFUzI1NiIsImtpZCI6IjEyIiwidHlwIjoic3RhdHVzbGlzdCtqd3QifQ.e
                            yJleHAiOjIyOTE3MjAxNzAsImlhdCI6MTY4NjkyMDE3MCwiaXNzIjoiaHR0cHM6Ly9le
                            GFtcGxlLmNvbSIsInN0YXR1c19saXN0Ijp7ImJpdHMiOjEsImxzdCI6ImVOcmJ1UmdBQ
                            WhjQlhRIn0sInN1YiI6Imh0dHBzOi8vZXhhbXBsZS5jb20vc3RhdHVzbGlzdHMvMSIsI
                            nR0bCI6NDMyMDB9.cyiLrzQVZvPnAXO07s7EzUqBB-62Sa39XfZMopIfEVQ819dBFvgv
                            wvQmJd8OHDj6l6Ct-tG3CLUG8LaxubYL6g
                        """.trimIndent().encodeToByteArray(),
                    )
                }

                else -> {
                    HttpResponseMessage(
                        controlData = HttpResponseMessageControlData(
                            statusCode = HttpStatusCode.OK,
                        ),
                        headers = listOf(
                            HttpFieldLine(
                                HttpFieldName.ContentType,
                                HttpFieldValue(MediaTypes.cwtStatusList),
                            )
                        ),
                        content = "d28453a20126106e7374617475736c6973742b637774a1044231325850a502782168747470733a2f2f6578616d706c652e636f6d2f7374617475736c697374732f31061a648c5bea041a8898dfea19fffe19a8c019fffda2646269747301636c73744a78dadbb918000217015d5840a58e97949e926d4d0e5340a7d103f0181aa35ed5ba1aaab42b9c058335de2cdf833dce0e7ebbc032b05615f1d2e70b53eb7275966ce834ddc42b76549d8a68b5".hexToByteArray(),
                    )
                }
            }
        }

        val statusResolver = StatusListTokenResolver.FromHttpRequestResolver(
            acceptedTypes = listOf(
                StatusListTokenMediaType.Jwt,
                StatusListTokenMediaType.Cwt,
            ),
            httpRequestResolver = httpResolver,
        ) { mediaType, byteArray ->
            when (mediaType) {
                StatusListTokenMediaType.Jwt -> {
                    WebToken.JsonWebToken(byteArray.decodeToString())
                }

                StatusListTokenMediaType.Cwt -> {
                    WebToken.CborWebToken(byteArray)
                }
            }
        }

        withData("jwt", "cwt") {
            shouldNotThrowAny {
                statusResolver.invoke(UniformResourceIdentifier("https://www.example.com/$it"))
            }
        }
    }
})
package at.asitplus.wallet.lib.third_party.kotlin

import io.ktor.util.encodeBase64


fun ByteArray.encodeBase64Url() = encodeBase64().base64ToBase64Url()
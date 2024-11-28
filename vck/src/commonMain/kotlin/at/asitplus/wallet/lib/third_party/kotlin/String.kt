package at.asitplus.wallet.lib.third_party.kotlin

import io.ktor.util.decodeBase64Bytes
import io.ktor.util.decodeBase64String
import io.ktor.util.encodeBase64

fun String.base64ToBase64Url() = replace('-', '+').replace('_', '/')
fun String.base64UrlToBase64() = replace('+', '-').replace('/', '_')

fun String.decodeBase64UrlString() = base64UrlToBase64().decodeBase64String()
fun String.decodeBase64UrlBytes() = base64UrlToBase64().decodeBase64Bytes()

fun String.encodeBase64Url() = encodeBase64().base64ToBase64Url()
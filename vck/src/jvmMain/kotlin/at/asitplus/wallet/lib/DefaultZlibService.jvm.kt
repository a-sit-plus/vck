package at.asitplus.wallet.lib

import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.util.zip.Deflater
import java.util.zip.DeflaterInputStream
import java.util.zip.InflaterInputStream

actual class DefaultZlibService actual constructor() : DefaultAndroidJvmZlibService()
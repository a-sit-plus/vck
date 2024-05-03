// Generated from C:/Users/stefan.kreiner/Documents/git/com.github/a-sit-plus/jsonpath/jsonpath/build/processedResources/iosArm64/main/grammar/JsonPathParser.g4 by ANTLR 4.13.1
package at.asitplus.jsonpath.generated

import com.strumenta.antlrkotlin.runtime.JsName
import org.antlr.v4.kotlinruntime.*
import org.antlr.v4.kotlinruntime.atn.*
import org.antlr.v4.kotlinruntime.atn.ATN.Companion.INVALID_ALT_NUMBER
import org.antlr.v4.kotlinruntime.dfa.*
import org.antlr.v4.kotlinruntime.misc.*
import org.antlr.v4.kotlinruntime.tree.*
import kotlin.jvm.JvmField

@Suppress(
    // This is required as we are using a custom JsName alias that is not recognized by the IDE.
    // No name clashes will happen tho.
    "JS_NAME_CLASH",
    "UNUSED_VARIABLE",
    "ClassName",
    "FunctionName",
    "LocalVariableName",
    "ConstPropertyName",
    "ConvertSecondaryConstructorToPrimary",
    "CanBeVal",
)
public open class JsonPathParser(input: TokenStream) : Parser(input) {
    private companion object {
        init {
            RuntimeMetaData.checkVersion("4.13.1", RuntimeMetaData.runtimeVersion)
        }

        private const val SERIALIZED_ATN: String =
            "\u0004\u0001\u001e\u0159\u0002\u0000\u0007\u0000\u0002\u0001\u0007\u0001\u0002\u0002\u0007\u0002\u0002\u0003\u0007\u0003\u0002\u0004\u0007\u0004\u0002\u0005\u0007\u0005\u0002\u0006\u0007\u0006\u0002\u0007\u0007\u0007\u0002\u0008\u0007\u0008\u0002\u0009\u0007\u0009\u0002\u000a\u0007\u000a\u0002\u000b\u0007\u000b\u0002\u000c\u0007\u000c\u0002\u000d\u0007\u000d\u0002\u000e\u0007\u000e\u0002\u000f\u0007\u000f\u0002\u0010\u0007\u0010\u0002\u0011\u0007\u0011\u0002\u0012\u0007\u0012\u0002\u0013\u0007\u0013\u0002\u0014\u0007\u0014\u0002\u0015\u0007\u0015\u0002\u0016\u0007\u0016\u0002\u0017\u0007\u0017\u0002\u0018\u0007\u0018\u0002\u0019\u0007\u0019\u0002\u001a\u0007\u001a\u0002\u001b\u0007\u001b\u0002\u001c\u0007\u001c\u0002\u001d\u0007\u001d\u0002\u001e\u0007\u001e\u0002\u001f\u0007\u001f\u0002\u0020\u0007\u0020\u0002\u0021\u0007\u0021\u0002\u0022\u0007\u0022\u0002\u0023\u0007\u0023\u0002\u0024\u0007\u0024\u0002\u0025\u0007\u0025\u0002\u0026\u0007\u0026\u0002\u0027\u0007\u0027\u0002\u0028\u0007\u0028\u0002\u0029\u0007\u0029\u0002\u002a\u0007\u002a\u0002\u002b\u0007\u002b\u0002\u002c\u0007\u002c\u0002\u002d\u0007\u002d\u0002\u002e\u0007\u002e\u0002\u002f\u0007\u002f\u0001\u0000\u0001\u0000\u0001\u0000\u0001\u0001\u0001\u0001\u0001\u0001\u0005\u0001\u0067\u0008\u0001\u000a\u0001\u000c\u0001\u006a\u0009\u0001\u0001\u0002\u0001\u0002\u0001\u0002\u0001\u0002\u0001\u0002\u0003\u0002\u0071\u0008\u0002\u0001\u0003\u0001\u0003\u0003\u0003\u0075\u0008\u0003\u0001\u0004\u0001\u0004\u0001\u0004\u0003\u0004\u007a\u0008\u0004\u0001\u0005\u0001\u0005\u0001\u0005\u0001\u0005\u0001\u0005\u0001\u0005\u0001\u0005\u0001\u0005\u0005\u0005\u0084\u0008\u0005\u000a\u0005\u000c\u0005\u0087\u0009\u0005\u0001\u0005\u0001\u0005\u0001\u0005\u0001\u0006\u0001\u0006\u0001\u0006\u0001\u0006\u0001\u0006\u0003\u0006\u0091\u0008\u0006\u0001\u0007\u0001\u0007\u0001\u0008\u0001\u0008\u0001\u0009\u0001\u0009\u0001\u0009\u0003\u0009\u009a\u0008\u0009\u0001\u0009\u0001\u0009\u0001\u0009\u0001\u0009\u0001\u0009\u0003\u0009\u00a1\u0008\u0009\u0001\u0009\u0001\u0009\u0001\u0009\u0001\u0009\u0003\u0009\u00a7\u0008\u0009\u0003\u0009\u00a9\u0008\u0009\u0001\u000a\u0001\u000a\u0001\u000b\u0001\u000b\u0001\u000c\u0001\u000c\u0001\u000d\u0001\u000d\u0003\u000d\u00b3\u0008\u000d\u0001\u000e\u0001\u000e\u0001\u000e\u0001\u000f\u0001\u000f\u0003\u000f\u00ba\u0008\u000f\u0001\u0010\u0001\u0010\u0001\u0010\u0001\u0011\u0001\u0011\u0001\u0011\u0001\u0012\u0001\u0012\u0001\u0012\u0005\u0012\u00c5\u0008\u0012\u000a\u0012\u000c\u0012\u00c8\u0009\u0012\u0001\u0013\u0001\u0013\u0003\u0013\u00cc\u0008\u0013\u0001\u0014\u0001\u0014\u0001\u0014\u0001\u0014\u0001\u0014\u0001\u0014\u0003\u0014\u00d4\u0008\u0014\u0001\u0015\u0001\u0015\u0001\u0015\u0001\u0015\u0001\u0016\u0001\u0016\u0001\u0016\u0001\u0016\u0001\u0017\u0001\u0017\u0001\u0018\u0001\u0018\u0001\u0018\u0001\u0018\u0001\u0018\u0001\u0018\u0005\u0018\u00e6\u0008\u0018\u000a\u0018\u000c\u0018\u00e9\u0009\u0018\u0001\u0019\u0001\u0019\u0001\u0019\u0001\u0019\u0001\u0019\u0001\u0019\u0005\u0019\u00f1\u0008\u0019\u000a\u0019\u000c\u0019\u00f4\u0009\u0019\u0001\u001a\u0001\u001a\u0001\u001a\u0003\u001a\u00f9\u0008\u001a\u0001\u001b\u0001\u001b\u0003\u001b\u00fd\u0008\u001b\u0001\u001b\u0001\u001b\u0001\u001b\u0001\u001b\u0001\u001b\u0001\u001b\u0001\u001c\u0001\u001c\u0003\u001c\u0107\u0008\u001c\u0001\u001c\u0001\u001c\u0003\u001c\u010b\u0008\u001c\u0001\u001d\u0001\u001d\u0001\u001d\u0001\u001d\u0001\u001d\u0001\u001d\u0001\u001e\u0001\u001e\u0001\u001f\u0001\u001f\u0001\u0020\u0001\u0020\u0001\u0020\u0001\u0020\u0001\u0020\u0001\u0020\u0003\u0020\u011d\u0008\u0020\u0001\u0021\u0001\u0021\u0001\u0021\u0003\u0021\u0122\u0008\u0021\u0001\u0022\u0001\u0022\u0001\u0022\u0001\u0022\u0001\u0022\u0001\u0022\u0001\u0022\u0001\u0022\u0001\u0022\u0005\u0022\u012d\u0008\u0022\u000a\u0022\u000c\u0022\u0130\u0009\u0022\u0003\u0022\u0132\u0008\u0022\u0001\u0022\u0001\u0022\u0001\u0022\u0001\u0023\u0001\u0023\u0001\u0023\u0001\u0023\u0003\u0023\u013b\u0008\u0023\u0001\u0024\u0001\u0024\u0001\u0025\u0001\u0025\u0001\u0026\u0005\u0026\u0142\u0008\u0026\u000a\u0026\u000c\u0026\u0145\u0009\u0026\u0001\u0027\u0001\u0027\u0001\u0028\u0001\u0028\u0001\u0029\u0001\u0029\u0001\u002a\u0001\u002a\u0001\u002b\u0001\u002b\u0001\u002c\u0001\u002c\u0001\u002d\u0001\u002d\u0001\u002e\u0001\u002e\u0001\u002f\u0001\u002f\u0001\u002f\u0000\u0000\u0030\u0000\u0002\u0004\u0006\u0008\u000a\u000c\u000e\u0010\u0012\u0014\u0016\u0018\u001a\u001c\u001e\u0020\u0022\u0024\u0026\u0028\u002a\u002c\u002e\u0030\u0032\u0034\u0036\u0038\u003a\u003c\u003e\u0040\u0042\u0044\u0046\u0048\u004a\u004c\u004e\u0050\u0052\u0054\u0056\u0058\u005a\u005c\u005e\u0000\u0001\u0001\u0000\u0011\u0016\u0150\u0000\u0060\u0001\u0000\u0000\u0000\u0002\u0068\u0001\u0000\u0000\u0000\u0004\u0070\u0001\u0000\u0000\u0000\u0006\u0074\u0001\u0000\u0000\u0000\u0008\u0079\u0001\u0000\u0000\u0000\u000a\u007b\u0001\u0000\u0000\u0000\u000c\u0090\u0001\u0000\u0000\u0000\u000e\u0092\u0001\u0000\u0000\u0000\u0010\u0094\u0001\u0000\u0000\u0000\u0012\u0099\u0001\u0000\u0000\u0000\u0014\u00aa\u0001\u0000\u0000\u0000\u0016\u00ac\u0001\u0000\u0000\u0000\u0018\u00ae\u0001\u0000\u0000\u0000\u001a\u00b2\u0001\u0000\u0000\u0000\u001c\u00b4\u0001\u0000\u0000\u0000\u001e\u00b9\u0001\u0000\u0000\u0000\u0020\u00bb\u0001\u0000\u0000\u0000\u0022\u00be\u0001\u0000\u0000\u0000\u0024\u00c6\u0001\u0000\u0000\u0000\u0026\u00cb\u0001\u0000\u0000\u0000\u0028\u00d3\u0001\u0000\u0000\u0000\u002a\u00d5\u0001\u0000\u0000\u0000\u002c\u00d9\u0001\u0000\u0000\u0000\u002e\u00dd\u0001\u0000\u0000\u0000\u0030\u00df\u0001\u0000\u0000\u0000\u0032\u00ea\u0001\u0000\u0000\u0000\u0034\u00f8\u0001\u0000\u0000\u0000\u0036\u00fc\u0001\u0000\u0000\u0000\u0038\u0106\u0001\u0000\u0000\u0000\u003a\u010c\u0001\u0000\u0000\u0000\u003c\u0112\u0001\u0000\u0000\u0000\u003e\u0114\u0001\u0000\u0000\u0000\u0040\u011c\u0001\u0000\u0000\u0000\u0042\u0121\u0001\u0000\u0000\u0000\u0044\u0123\u0001\u0000\u0000\u0000\u0046\u013a\u0001\u0000\u0000\u0000\u0048\u013c\u0001\u0000\u0000\u0000\u004a\u013e\u0001\u0000\u0000\u0000\u004c\u0143\u0001\u0000\u0000\u0000\u004e\u0146\u0001\u0000\u0000\u0000\u0050\u0148\u0001\u0000\u0000\u0000\u0052\u014a\u0001\u0000\u0000\u0000\u0054\u014c\u0001\u0000\u0000\u0000\u0056\u014e\u0001\u0000\u0000\u0000\u0058\u0150\u0001\u0000\u0000\u0000\u005a\u0152\u0001\u0000\u0000\u0000\u005c\u0154\u0001\u0000\u0000\u0000\u005e\u0156\u0001\u0000\u0000\u0000\u0060\u0061\u0003\u0048\u0024\u0000\u0061\u0062\u0003\u0002\u0001\u0000\u0062\u0001\u0001\u0000\u0000\u0000\u0063\u0064\u0003\u004c\u0026\u0000\u0064\u0065\u0003\u0004\u0002\u0000\u0065\u0067\u0001\u0000\u0000\u0000\u0066\u0063\u0001\u0000\u0000\u0000\u0067\u006a\u0001\u0000\u0000\u0000\u0068\u0066\u0001\u0000\u0000\u0000\u0068\u0069\u0001\u0000\u0000\u0000\u0069\u0003\u0001\u0000\u0000\u0000\u006a\u0068\u0001\u0000\u0000\u0000\u006b\u0071\u0003\u000a\u0005\u0000\u006c\u006d\u0005\u0005\u0000\u0000\u006d\u0071\u0003\u0006\u0003\u0000\u006e\u006f\u0005\u0004\u0000\u0000\u006f\u0071\u0003\u0008\u0004\u0000\u0070\u006b\u0001\u0000\u0000\u0000\u0070\u006c\u0001\u0000\u0000\u0000\u0070\u006e\u0001\u0000\u0000\u0000\u0071\u0005\u0001\u0000\u0000\u0000\u0072\u0075\u0003\u004e\u0027\u0000\u0073\u0075\u0003\u0050\u0028\u0000\u0074\u0072\u0001\u0000\u0000\u0000\u0074\u0073\u0001\u0000\u0000\u0000\u0075\u0007\u0001\u0000\u0000\u0000\u0076\u007a\u0003\u000a\u0005\u0000\u0077\u007a\u0003\u004e\u0027\u0000\u0078\u007a\u0003\u0050\u0028\u0000\u0079\u0076\u0001\u0000\u0000\u0000\u0079\u0077\u0001\u0000\u0000\u0000\u0079\u0078\u0001\u0000\u0000\u0000\u007a\u0009\u0001\u0000\u0000\u0000\u007b\u007c\u0005\u0009\u0000\u0000\u007c\u007d\u0003\u004c\u0026\u0000\u007d\u0085\u0003\u000c\u0006\u0000\u007e\u007f\u0003\u004c\u0026\u0000\u007f\u0080\u0005\u0008\u0000\u0000\u0080\u0081\u0003\u004c\u0026\u0000\u0081\u0082\u0003\u000c\u0006\u0000\u0082\u0084\u0001\u0000\u0000\u0000\u0083\u007e\u0001\u0000\u0000\u0000\u0084\u0087\u0001\u0000\u0000\u0000\u0085\u0083\u0001\u0000\u0000\u0000\u0085\u0086\u0001\u0000\u0000\u0000\u0086\u0088\u0001\u0000\u0000\u0000\u0087\u0085\u0001\u0000\u0000\u0000\u0088\u0089\u0003\u004c\u0026\u0000\u0089\u008a\u0005\u000a\u0000\u0000\u008a\u000b\u0001\u0000\u0000\u0000\u008b\u0091\u0003\u000e\u0007\u0000\u008c\u0091\u0003\u004e\u0027\u0000\u008d\u0091\u0003\u0012\u0009\u0000\u008e\u0091\u0003\u0010\u0008\u0000\u008f\u0091\u0003\u002c\u0016\u0000\u0090\u008b\u0001\u0000\u0000\u0000\u0090\u008c\u0001\u0000\u0000\u0000\u0090\u008d\u0001\u0000\u0000\u0000\u0090\u008e\u0001\u0000\u0000\u0000\u0090\u008f\u0001\u0000\u0000\u0000\u0091\u000d\u0001\u0000\u0000\u0000\u0092\u0093\u0003\u0052\u0029\u0000\u0093\u000f\u0001\u0000\u0000\u0000\u0094\u0095\u0003\u0056\u002b\u0000\u0095\u0011\u0001\u0000\u0000\u0000\u0096\u0097\u0003\u0014\u000a\u0000\u0097\u0098\u0003\u004c\u0026\u0000\u0098\u009a\u0001\u0000\u0000\u0000\u0099\u0096\u0001\u0000\u0000\u0000\u0099\u009a\u0001\u0000\u0000\u0000\u009a\u009b\u0001\u0000\u0000\u0000\u009b\u009c\u0005\u0007\u0000\u0000\u009c\u00a0\u0003\u004c\u0026\u0000\u009d\u009e\u0003\u0016\u000b\u0000\u009e\u009f\u0003\u004c\u0026\u0000\u009f\u00a1\u0001\u0000\u0000\u0000\u00a0\u009d\u0001\u0000\u0000\u0000\u00a0\u00a1\u0001\u0000\u0000\u0000\u00a1\u00a8\u0001\u0000\u0000\u0000\u00a2\u00a6\u0005\u0007\u0000\u0000\u00a3\u00a4\u0003\u004c\u0026\u0000\u00a4\u00a5\u0003\u0018\u000c\u0000\u00a5\u00a7\u0001\u0000\u0000\u0000\u00a6\u00a3\u0001\u0000\u0000\u0000\u00a6\u00a7\u0001\u0000\u0000\u0000\u00a7\u00a9\u0001\u0000\u0000\u0000\u00a8\u00a2\u0001\u0000\u0000\u0000\u00a8\u00a9\u0001\u0000\u0000\u0000\u00a9\u0013\u0001\u0000\u0000\u0000\u00aa\u00ab\u0003\u0056\u002b\u0000\u00ab\u0015\u0001\u0000\u0000\u0000\u00ac\u00ad\u0003\u0056\u002b\u0000\u00ad\u0017\u0001\u0000\u0000\u0000\u00ae\u00af\u0003\u0056\u002b\u0000\u00af\u0019\u0001\u0000\u0000\u0000\u00b0\u00b3\u0003\u001c\u000e\u0000\u00b1\u00b3\u0003\u0000\u0000\u0000\u00b2\u00b0\u0001\u0000\u0000\u0000\u00b2\u00b1\u0001\u0000\u0000\u0000\u00b3\u001b\u0001\u0000\u0000\u0000\u00b4\u00b5\u0003\u004a\u0025\u0000\u00b5\u00b6\u0003\u0002\u0001\u0000\u00b6\u001d\u0001\u0000\u0000\u0000\u00b7\u00ba\u0003\u0020\u0010\u0000\u00b8\u00ba\u0003\u0022\u0011\u0000\u00b9\u00b7\u0001\u0000\u0000\u0000\u00b9\u00b8\u0001\u0000\u0000\u0000\u00ba\u001f\u0001\u0000\u0000\u0000\u00bb\u00bc\u0003\u004a\u0025\u0000\u00bc\u00bd\u0003\u0024\u0012\u0000\u00bd\u0021\u0001\u0000\u0000\u0000\u00be\u00bf\u0003\u0048\u0024\u0000\u00bf\u00c0\u0003\u0024\u0012\u0000\u00c0\u0023\u0001\u0000\u0000\u0000\u00c1\u00c2\u0003\u004c\u0026\u0000\u00c2\u00c3\u0003\u0026\u0013\u0000\u00c3\u00c5\u0001\u0000\u0000\u0000\u00c4\u00c1\u0001\u0000\u0000\u0000\u00c5\u00c8\u0001\u0000\u0000\u0000\u00c6\u00c4\u0001\u0000\u0000\u0000\u00c6\u00c7\u0001\u0000\u0000\u0000\u00c7\u0025\u0001\u0000\u0000\u0000\u00c8\u00c6\u0001\u0000\u0000\u0000\u00c9\u00cc\u0003\u0028\u0014\u0000\u00ca\u00cc\u0003\u002a\u0015\u0000\u00cb\u00c9\u0001\u0000\u0000\u0000\u00cb\u00ca\u0001\u0000\u0000\u0000\u00cc\u0027\u0001\u0000\u0000\u0000\u00cd\u00ce\u0005\u0009\u0000\u0000\u00ce\u00cf\u0003\u000e\u0007\u0000\u00cf\u00d0\u0005\u000a\u0000\u0000\u00d0\u00d4\u0001\u0000\u0000\u0000\u00d1\u00d2\u0005\u0005\u0000\u0000\u00d2\u00d4\u0003\u0050\u0028\u0000\u00d3\u00cd\u0001\u0000\u0000\u0000\u00d3\u00d1\u0001\u0000\u0000\u0000\u00d4\u0029\u0001\u0000\u0000\u0000\u00d5\u00d6\u0005\u0009\u0000\u0000\u00d6\u00d7\u0003\u0010\u0008\u0000\u00d7\u00d8\u0005\u000a\u0000\u0000\u00d8\u002b\u0001\u0000\u0000\u0000\u00d9\u00da\u0005\u000b\u0000\u0000\u00da\u00db\u0003\u004c\u0026\u0000\u00db\u00dc\u0003\u002e\u0017\u0000\u00dc\u002d\u0001\u0000\u0000\u0000\u00dd\u00de\u0003\u0030\u0018\u0000\u00de\u002f\u0001\u0000\u0000\u0000\u00df\u00e7\u0003\u0032\u0019\u0000\u00e0\u00e1\u0003\u004c\u0026\u0000\u00e1\u00e2\u0005\u000f\u0000\u0000\u00e2\u00e3\u0003\u004c\u0026\u0000\u00e3\u00e4\u0003\u0032\u0019\u0000\u00e4\u00e6\u0001\u0000\u0000\u0000\u00e5\u00e0\u0001\u0000\u0000\u0000\u00e6\u00e9\u0001\u0000\u0000\u0000\u00e7\u00e5\u0001\u0000\u0000\u0000\u00e7\u00e8\u0001\u0000\u0000\u0000\u00e8\u0031\u0001\u0000\u0000\u0000\u00e9\u00e7\u0001\u0000\u0000\u0000\u00ea\u00f2\u0003\u0034\u001a\u0000\u00eb\u00ec\u0003\u004c\u0026\u0000\u00ec\u00ed\u0005\u0010\u0000\u0000\u00ed\u00ee\u0003\u004c\u0026\u0000\u00ee\u00ef\u0003\u0034\u001a\u0000\u00ef\u00f1\u0001\u0000\u0000\u0000\u00f0\u00eb\u0001\u0000\u0000\u0000\u00f1\u00f4\u0001\u0000\u0000\u0000\u00f2\u00f0\u0001\u0000\u0000\u0000\u00f2\u00f3\u0001\u0000\u0000\u0000\u00f3\u0033\u0001\u0000\u0000\u0000\u00f4\u00f2\u0001\u0000\u0000\u0000\u00f5\u00f9\u0003\u0036\u001b\u0000\u00f6\u00f9\u0003\u003a\u001d\u0000\u00f7\u00f9\u0003\u0038\u001c\u0000\u00f8\u00f5\u0001\u0000\u0000\u0000\u00f8\u00f6\u0001\u0000\u0000\u0000\u00f8\u00f7\u0001\u0000\u0000\u0000\u00f9\u0035\u0001\u0000\u0000\u0000\u00fa\u00fb\u0005\u000e\u0000\u0000\u00fb\u00fd\u0003\u004c\u0026\u0000\u00fc\u00fa\u0001\u0000\u0000\u0000\u00fc\u00fd\u0001\u0000\u0000\u0000\u00fd\u00fe\u0001\u0000\u0000\u0000\u00fe\u00ff\u0005\u000c\u0000\u0000\u00ff\u0100\u0003\u004c\u0026\u0000\u0100\u0101\u0003\u002e\u0017\u0000\u0101\u0102\u0003\u004c\u0026\u0000\u0102\u0103\u0005\u000d\u0000\u0000\u0103\u0037\u0001\u0000\u0000\u0000\u0104\u0105\u0005\u000e\u0000\u0000\u0105\u0107\u0003\u004c\u0026\u0000\u0106\u0104\u0001\u0000\u0000\u0000\u0106\u0107\u0001\u0000\u0000\u0000\u0107\u010a\u0001\u0000\u0000\u0000\u0108\u010b\u0003\u001a\u000d\u0000\u0109\u010b\u0003\u0044\u0022\u0000\u010a\u0108\u0001\u0000\u0000\u0000\u010a\u0109\u0001\u0000\u0000\u0000\u010b\u0039\u0001\u0000\u0000\u0000\u010c\u010d\u0003\u003c\u001e\u0000\u010d\u010e\u0003\u004c\u0026\u0000\u010e\u010f\u0003\u005e\u002f\u0000\u010f\u0110\u0003\u004c\u0026\u0000\u0110\u0111\u0003\u003e\u001f\u0000\u0111\u003b\u0001\u0000\u0000\u0000\u0112\u0113\u0003\u0042\u0021\u0000\u0113\u003d\u0001\u0000\u0000\u0000\u0114\u0115\u0003\u0042\u0021\u0000\u0115\u003f\u0001\u0000\u0000\u0000\u0116\u011d\u0003\u0056\u002b\u0000\u0117\u011d\u0003\u0054\u002a\u0000\u0118\u011d\u0003\u0052\u0029\u0000\u0119\u011d\u0003\u0058\u002c\u0000\u011a\u011d\u0003\u005a\u002d\u0000\u011b\u011d\u0003\u005c\u002e\u0000\u011c\u0116\u0001\u0000\u0000\u0000\u011c\u0117\u0001\u0000\u0000\u0000\u011c\u0118\u0001\u0000\u0000\u0000\u011c\u0119\u0001\u0000\u0000\u0000\u011c\u011a\u0001\u0000\u0000\u0000\u011c\u011b\u0001\u0000\u0000\u0000\u011d\u0041\u0001\u0000\u0000\u0000\u011e\u0122\u0003\u0040\u0020\u0000\u011f\u0122\u0003\u001e\u000f\u0000\u0120\u0122\u0003\u0044\u0022\u0000\u0121\u011e\u0001\u0000\u0000\u0000\u0121\u011f\u0001\u0000\u0000\u0000\u0121\u0120\u0001\u0000\u0000\u0000\u0122\u0043\u0001\u0000\u0000\u0000\u0123\u0124\u0005\u001d\u0000\u0000\u0124\u0125\u0005\u000c\u0000\u0000\u0125\u0131\u0003\u004c\u0026\u0000\u0126\u012e\u0003\u0046\u0023\u0000\u0127\u0128\u0003\u004c\u0026\u0000\u0128\u0129\u0005\u0008\u0000\u0000\u0129\u012a\u0003\u004c\u0026\u0000\u012a\u012b\u0003\u0046\u0023\u0000\u012b\u012d\u0001\u0000\u0000\u0000\u012c\u0127\u0001\u0000\u0000\u0000\u012d\u0130\u0001\u0000\u0000\u0000\u012e\u012c\u0001\u0000\u0000\u0000\u012e\u012f\u0001\u0000\u0000\u0000\u012f\u0132\u0001\u0000\u0000\u0000\u0130\u012e\u0001\u0000\u0000\u0000\u0131\u0126\u0001\u0000\u0000\u0000\u0131\u0132\u0001\u0000\u0000\u0000\u0132\u0133\u0001\u0000\u0000\u0000\u0133\u0134\u0003\u004c\u0026\u0000\u0134\u0135\u0005\u000d\u0000\u0000\u0135\u0045\u0001\u0000\u0000\u0000\u0136\u013b\u0003\u0040\u0020\u0000\u0137\u013b\u0003\u001a\u000d\u0000\u0138\u013b\u0003\u0044\u0022\u0000\u0139\u013b\u0003\u002e\u0017\u0000\u013a\u0136\u0001\u0000\u0000\u0000\u013a\u0137\u0001\u0000\u0000\u0000\u013a\u0138\u0001\u0000\u0000\u0000\u013a\u0139\u0001\u0000\u0000\u0000\u013b\u0047\u0001\u0000\u0000\u0000\u013c\u013d\u0005\u0001\u0000\u0000\u013d\u0049\u0001\u0000\u0000\u0000\u013e\u013f\u0005\u0002\u0000\u0000\u013f\u004b\u0001\u0000\u0000\u0000\u0140\u0142\u0005\u0003\u0000\u0000\u0141\u0140\u0001\u0000\u0000\u0000\u0142\u0145\u0001\u0000\u0000\u0000\u0143\u0141\u0001\u0000\u0000\u0000\u0143\u0144\u0001\u0000\u0000\u0000\u0144\u004d\u0001\u0000\u0000\u0000\u0145\u0143\u0001\u0000\u0000\u0000\u0146\u0147\u0005\u0006\u0000\u0000\u0147\u004f\u0001\u0000\u0000\u0000\u0148\u0149\u0005\u001e\u0000\u0000\u0149\u0051\u0001\u0000\u0000\u0000\u014a\u014b\u0005\u0017\u0000\u0000\u014b\u0053\u0001\u0000\u0000\u0000\u014c\u014d\u0005\u001c\u0000\u0000\u014d\u0055\u0001\u0000\u0000\u0000\u014e\u014f\u0005\u001b\u0000\u0000\u014f\u0057\u0001\u0000\u0000\u0000\u0150\u0151\u0005\u0019\u0000\u0000\u0151\u0059\u0001\u0000\u0000\u0000\u0152\u0153\u0005\u001a\u0000\u0000\u0153\u005b\u0001\u0000\u0000\u0000\u0154\u0155\u0005\u0018\u0000\u0000\u0155\u005d\u0001\u0000\u0000\u0000\u0156\u0157\u0007\u0000\u0000\u0000\u0157\u005f\u0001\u0000\u0000\u0000\u001b\u0068\u0070\u0074\u0079\u0085\u0090\u0099\u00a0\u00a6\u00a8\u00b2\u00b9\u00c6\u00cb\u00d3\u00e7\u00f2\u00f8\u00fc\u0106\u010a\u011c\u0121\u012e\u0131\u013a\u0143"

        private val ATN = ATNDeserializer().deserialize(SERIALIZED_ATN.toCharArray())

        private val DECISION_TO_DFA = Array(ATN.numberOfDecisions) {
            DFA(ATN.getDecisionState(it)!!, it)
        }

        private val SHARED_CONTEXT_CACHE = PredictionContextCache()
        private val RULE_NAMES: Array<String> = arrayOf(
            "jsonpath_query", "segments", "segment", "shorthand_segment", 
            "descendant_segment", "bracketed_selection", "selector", "name_selector", 
            "index_selector", "slice_selector", "start", "end", "step", 
            "filter_query", "rel_query", "singular_query", "rel_singular_query", 
            "abs_singular_query", "singular_query_segments", "singular_query_segment", 
            "name_segment", "index_segment", "filter_selector", "logical_expr", 
            "logical_or_expr", "logical_and_expr", "basic_expr", "paren_expr", 
            "test_expr", "comparison_expr", "firstComparable", "secondComparable", 
            "literal", "comparable", "function_expr", "function_argument", 
            "rootIdentifier", "currentNodeIdentifier", "ws", "wildcardSelector", 
            "memberNameShorthand", "stringLiteral", "number", "int", "true", 
            "false", "null", "comparisonOp"
        )

        private val LITERAL_NAMES: Array<String?> = arrayOf(
            null, "'\$'", "'@'", null, "'..'", "'.'", null, "':'", "','", 
            null, "']'", "'?'", "'('", "')'", "'!'", "'||'", "'&&'", "'=='", 
            "'!='", "'<'", "'>'", "'<='", "'>='", null, "'null'", "'true'", 
            "'false'"
        )

        private val SYMBOLIC_NAMES: Array<String?> = arrayOf(
            null, "ROOT_IDENTIFIER", "CURRENT_NODE_IDENTIFIER", "BLANK", 
            "DESCENDANT_SELECTOR", "SHORTHAND_SELECTOR", "WILDCARD_SELECTOR", 
            "COLON", "COMMA", "SQUARE_BRACKET_OPEN", "SQUARE_BRACKET_CLOSE", 
            "QUESTIONMARK", "BRACKET_OPEN", "BRACKET_CLOSE", "LOGICAL_NOT_OP", 
            "LOGICAL_OR_OP", "LOGICAL_AND_OP", "COMPARISON_OP_EQUALS", "COMPARISON_OP_NOT_EQUALS", 
            "COMPARISON_OP_SMALLER_THAN", "COMPARISON_OP_GREATER_THAN", 
            "COMPARISON_OP_SMALLER_THAN_OR_EQUALS", "COMPARISON_OP_GREATER_THAN_OR_EQUALS", 
            "STRING_LITERAL", "NULL", "TRUE", "FALSE", "INT", "NUMBER", 
            "FUNCTION_NAME", "MEMBER_NAME_SHORTHAND"
        )

        private val VOCABULARY = VocabularyImpl(LITERAL_NAMES, SYMBOLIC_NAMES)

        private val TOKEN_NAMES: Array<String> = Array(SYMBOLIC_NAMES.size) {
            VOCABULARY.getLiteralName(it)
                ?: VOCABULARY.getSymbolicName(it)
                ?: "<INVALID>"
        }
    }

    public object Tokens {
        public const val EOF: Int = -1
        public const val ROOT_IDENTIFIER: Int = 1
        public const val CURRENT_NODE_IDENTIFIER: Int = 2
        public const val BLANK: Int = 3
        public const val DESCENDANT_SELECTOR: Int = 4
        public const val SHORTHAND_SELECTOR: Int = 5
        public const val WILDCARD_SELECTOR: Int = 6
        public const val COLON: Int = 7
        public const val COMMA: Int = 8
        public const val SQUARE_BRACKET_OPEN: Int = 9
        public const val SQUARE_BRACKET_CLOSE: Int = 10
        public const val QUESTIONMARK: Int = 11
        public const val BRACKET_OPEN: Int = 12
        public const val BRACKET_CLOSE: Int = 13
        public const val LOGICAL_NOT_OP: Int = 14
        public const val LOGICAL_OR_OP: Int = 15
        public const val LOGICAL_AND_OP: Int = 16
        public const val COMPARISON_OP_EQUALS: Int = 17
        public const val COMPARISON_OP_NOT_EQUALS: Int = 18
        public const val COMPARISON_OP_SMALLER_THAN: Int = 19
        public const val COMPARISON_OP_GREATER_THAN: Int = 20
        public const val COMPARISON_OP_SMALLER_THAN_OR_EQUALS: Int = 21
        public const val COMPARISON_OP_GREATER_THAN_OR_EQUALS: Int = 22
        public const val STRING_LITERAL: Int = 23
        public const val NULL: Int = 24
        public const val TRUE: Int = 25
        public const val FALSE: Int = 26
        public const val INT: Int = 27
        public const val NUMBER: Int = 28
        public const val FUNCTION_NAME: Int = 29
        public const val MEMBER_NAME_SHORTHAND: Int = 30
    }

    public object Rules {
        public const val Jsonpath_query: Int = 0
        public const val Segments: Int = 1
        public const val Segment: Int = 2
        public const val Shorthand_segment: Int = 3
        public const val Descendant_segment: Int = 4
        public const val Bracketed_selection: Int = 5
        public const val Selector: Int = 6
        public const val Name_selector: Int = 7
        public const val Index_selector: Int = 8
        public const val Slice_selector: Int = 9
        public const val Start: Int = 10
        public const val End: Int = 11
        public const val Step: Int = 12
        public const val Filter_query: Int = 13
        public const val Rel_query: Int = 14
        public const val Singular_query: Int = 15
        public const val Rel_singular_query: Int = 16
        public const val Abs_singular_query: Int = 17
        public const val Singular_query_segments: Int = 18
        public const val Singular_query_segment: Int = 19
        public const val Name_segment: Int = 20
        public const val Index_segment: Int = 21
        public const val Filter_selector: Int = 22
        public const val Logical_expr: Int = 23
        public const val Logical_or_expr: Int = 24
        public const val Logical_and_expr: Int = 25
        public const val Basic_expr: Int = 26
        public const val Paren_expr: Int = 27
        public const val Test_expr: Int = 28
        public const val Comparison_expr: Int = 29
        public const val FirstComparable: Int = 30
        public const val SecondComparable: Int = 31
        public const val Literal: Int = 32
        public const val Comparable: Int = 33
        public const val Function_expr: Int = 34
        public const val Function_argument: Int = 35
        public const val RootIdentifier: Int = 36
        public const val CurrentNodeIdentifier: Int = 37
        public const val Ws: Int = 38
        public const val WildcardSelector: Int = 39
        public const val MemberNameShorthand: Int = 40
        public const val StringLiteral: Int = 41
        public const val Number: Int = 42
        public const val Int: Int = 43
        public const val True: Int = 44
        public const val False: Int = 45
        public const val Null: Int = 46
        public const val ComparisonOp: Int = 47
    }

    override var interpreter: ParserATNSimulator =
        @Suppress("LeakingThis")
        ParserATNSimulator(this, ATN, DECISION_TO_DFA, SHARED_CONTEXT_CACHE)

    override val grammarFileName: String =
        "JsonPathParser.g4"

    @Deprecated("Use vocabulary instead", replaceWith = ReplaceWith("vocabulary"))
    override val tokenNames: Array<String> =
        TOKEN_NAMES

    override val ruleNames: Array<String> =
        RULE_NAMES

    override val atn: ATN =
        ATN

    override val vocabulary: Vocabulary =
        VOCABULARY

    override val serializedATN: String =
        SERIALIZED_ATN

    /* Named actions */

    /* Funcs */
    public open class Jsonpath_queryContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Jsonpath_query

        public fun rootIdentifier(): RootIdentifierContext = getRuleContext(RootIdentifierContext::class, 0)!!
        public fun segments(): SegmentsContext = getRuleContext(SegmentsContext::class, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterJsonpath_query(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitJsonpath_query(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitJsonpath_query(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun jsonpath_query(): Jsonpath_queryContext {
        var _localctx = Jsonpath_queryContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 0, Rules.Jsonpath_query)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 96
            rootIdentifier()

            this.state = 97
            segments()

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class SegmentsContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Segments

        public fun ws(): List<WsContext> = getRuleContexts(WsContext::class)
        public fun ws(i: Int): WsContext? = getRuleContext(WsContext::class, i)
        public fun segment(): List<SegmentContext> = getRuleContexts(SegmentContext::class)
        public fun segment(i: Int): SegmentContext? = getRuleContext(SegmentContext::class, i)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterSegments(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitSegments(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitSegments(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun segments(): SegmentsContext {
        var _localctx = SegmentsContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 2, Rules.Segments)

        try {
            var _alt: Int
            enterOuterAlt(_localctx, 1)
            this.state = 104
            errorHandler.sync(this)
            _alt = interpreter.adaptivePredict(_input, 0, context)

            while (_alt != 2 && _alt != INVALID_ALT_NUMBER) {
                if (_alt == 1 ) {
                    this.state = 99
                    ws()

                    this.state = 100
                    segment()
             
                }

                this.state = 106
                errorHandler.sync(this)
                _alt = interpreter.adaptivePredict(_input, 0, context)
            }
        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class SegmentContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Segment

        public fun bracketed_selection(): Bracketed_selectionContext? = getRuleContext(
            Bracketed_selectionContext::class, 0)
        public fun SHORTHAND_SELECTOR(): TerminalNode? = getToken(Tokens.SHORTHAND_SELECTOR, 0)
        public fun shorthand_segment(): Shorthand_segmentContext? = getRuleContext(
            Shorthand_segmentContext::class, 0)
        public fun DESCENDANT_SELECTOR(): TerminalNode? = getToken(Tokens.DESCENDANT_SELECTOR, 0)
        public fun descendant_segment(): Descendant_segmentContext? = getRuleContext(
            Descendant_segmentContext::class, 0)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterSegment(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitSegment(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitSegment(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun segment(): SegmentContext {
        var _localctx = SegmentContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 4, Rules.Segment)

        try {
            this.state = 112
            errorHandler.sync(this)

            when (_input.LA(1)) {
                Tokens.SQUARE_BRACKET_OPEN -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 1)
                    this.state = 107
                    bracketed_selection()

                }

                Tokens.SHORTHAND_SELECTOR -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 2)
                    this.state = 108
                    match(Tokens.SHORTHAND_SELECTOR)

                    this.state = 109
                    shorthand_segment()

                }

                Tokens.DESCENDANT_SELECTOR -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 3)
                    this.state = 110
                    match(Tokens.DESCENDANT_SELECTOR)

                    this.state = 111
                    descendant_segment()

                }
                else -> throw NoViableAltException(this)
            }
        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Shorthand_segmentContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Shorthand_segment

        public fun wildcardSelector(): WildcardSelectorContext? = getRuleContext(
            WildcardSelectorContext::class, 0)
        public fun memberNameShorthand(): MemberNameShorthandContext? = getRuleContext(
            MemberNameShorthandContext::class, 0)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterShorthand_segment(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitShorthand_segment(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitShorthand_segment(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun shorthand_segment(): Shorthand_segmentContext {
        var _localctx = Shorthand_segmentContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 6, Rules.Shorthand_segment)

        try {
            this.state = 116
            errorHandler.sync(this)

            when (_input.LA(1)) {
                Tokens.WILDCARD_SELECTOR -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 1)
                    this.state = 114
                    wildcardSelector()

                }

                Tokens.MEMBER_NAME_SHORTHAND -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 2)
                    this.state = 115
                    memberNameShorthand()

                }
                else -> throw NoViableAltException(this)
            }
        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Descendant_segmentContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Descendant_segment

        public fun bracketed_selection(): Bracketed_selectionContext? = getRuleContext(
            Bracketed_selectionContext::class, 0)
        public fun wildcardSelector(): WildcardSelectorContext? = getRuleContext(
            WildcardSelectorContext::class, 0)
        public fun memberNameShorthand(): MemberNameShorthandContext? = getRuleContext(
            MemberNameShorthandContext::class, 0)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterDescendant_segment(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitDescendant_segment(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitDescendant_segment(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun descendant_segment(): Descendant_segmentContext {
        var _localctx = Descendant_segmentContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 8, Rules.Descendant_segment)

        try {
            this.state = 121
            errorHandler.sync(this)

            when (_input.LA(1)) {
                Tokens.SQUARE_BRACKET_OPEN -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 1)
                    this.state = 118
                    bracketed_selection()

                }

                Tokens.WILDCARD_SELECTOR -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 2)
                    this.state = 119
                    wildcardSelector()

                }

                Tokens.MEMBER_NAME_SHORTHAND -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 3)
                    this.state = 120
                    memberNameShorthand()

                }
                else -> throw NoViableAltException(this)
            }
        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Bracketed_selectionContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Bracketed_selection

        public fun SQUARE_BRACKET_OPEN(): TerminalNode = getToken(Tokens.SQUARE_BRACKET_OPEN, 0)!!
        public fun ws(): List<WsContext> = getRuleContexts(WsContext::class)
        public fun ws(i: Int): WsContext? = getRuleContext(WsContext::class, i)
        public fun selector(): List<SelectorContext> = getRuleContexts(SelectorContext::class)
        public fun selector(i: Int): SelectorContext? = getRuleContext(SelectorContext::class, i)
        public fun SQUARE_BRACKET_CLOSE(): TerminalNode = getToken(Tokens.SQUARE_BRACKET_CLOSE, 0)!!
        public fun COMMA(): List<TerminalNode> = getTokens(Tokens.COMMA)
        public fun COMMA(i: Int): TerminalNode? = getToken(Tokens.COMMA, i)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterBracketed_selection(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitBracketed_selection(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitBracketed_selection(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun bracketed_selection(): Bracketed_selectionContext {
        var _localctx = Bracketed_selectionContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 10, Rules.Bracketed_selection)

        try {
            var _alt: Int
            enterOuterAlt(_localctx, 1)
            this.state = 123
            match(Tokens.SQUARE_BRACKET_OPEN)

            this.state = 124
            ws()

            this.state = 125
            selector()

            this.state = 133
            errorHandler.sync(this)
            _alt = interpreter.adaptivePredict(_input, 4, context)

            while (_alt != 2 && _alt != INVALID_ALT_NUMBER) {
                if (_alt == 1 ) {
                    this.state = 126
                    ws()

                    this.state = 127
                    match(Tokens.COMMA)

                    this.state = 128
                    ws()

                    this.state = 129
                    selector()
             
                }

                this.state = 135
                errorHandler.sync(this)
                _alt = interpreter.adaptivePredict(_input, 4, context)
            }
            this.state = 136
            ws()

            this.state = 137
            match(Tokens.SQUARE_BRACKET_CLOSE)

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class SelectorContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Selector

        public fun name_selector(): Name_selectorContext? = getRuleContext(Name_selectorContext::class, 0)
        public fun wildcardSelector(): WildcardSelectorContext? = getRuleContext(
            WildcardSelectorContext::class, 0)
        public fun slice_selector(): Slice_selectorContext? = getRuleContext(Slice_selectorContext::class, 0)
        public fun index_selector(): Index_selectorContext? = getRuleContext(Index_selectorContext::class, 0)
        public fun filter_selector(): Filter_selectorContext? = getRuleContext(
            Filter_selectorContext::class, 0)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterSelector(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitSelector(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitSelector(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun selector(): SelectorContext {
        var _localctx = SelectorContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 12, Rules.Selector)

        try {
            this.state = 144
            errorHandler.sync(this)

            when (interpreter.adaptivePredict(_input, 5, context)) {
                1 -> {
                    enterOuterAlt(_localctx, 1)
                    this.state = 139
                    name_selector()

                }2 -> {
                    enterOuterAlt(_localctx, 2)
                    this.state = 140
                    wildcardSelector()

                }3 -> {
                    enterOuterAlt(_localctx, 3)
                    this.state = 141
                    slice_selector()

                }4 -> {
                    enterOuterAlt(_localctx, 4)
                    this.state = 142
                    index_selector()

                }5 -> {
                    enterOuterAlt(_localctx, 5)
                    this.state = 143
                    filter_selector()

                }
            }
        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Name_selectorContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Name_selector

        public fun stringLiteral(): StringLiteralContext = getRuleContext(StringLiteralContext::class, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterName_selector(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitName_selector(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitName_selector(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun name_selector(): Name_selectorContext {
        var _localctx = Name_selectorContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 14, Rules.Name_selector)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 146
            stringLiteral()

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Index_selectorContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Index_selector

        public fun int(): IntContext = getRuleContext(IntContext::class, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterIndex_selector(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitIndex_selector(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitIndex_selector(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun index_selector(): Index_selectorContext {
        var _localctx = Index_selectorContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 16, Rules.Index_selector)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 148
            int()

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Slice_selectorContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Slice_selector

        public fun COLON(): List<TerminalNode> = getTokens(Tokens.COLON)
        public fun COLON(i: Int): TerminalNode? = getToken(Tokens.COLON, i)
        public fun ws(): List<WsContext> = getRuleContexts(WsContext::class)
        public fun ws(i: Int): WsContext? = getRuleContext(WsContext::class, i)
        public fun start(): StartContext? = getRuleContext(StartContext::class, 0)
        public fun end(): EndContext? = getRuleContext(EndContext::class, 0)
        public fun step(): StepContext? = getRuleContext(StepContext::class, 0)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterSlice_selector(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitSlice_selector(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitSlice_selector(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun slice_selector(): Slice_selectorContext {
        var _localctx = Slice_selectorContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 18, Rules.Slice_selector)
        var _la: Int

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 153
            errorHandler.sync(this)
            _la = _input.LA(1)

            if (_la == Tokens.INT) {
                this.state = 150
                start()

                this.state = 151
                ws()

            }
            this.state = 155
            match(Tokens.COLON)

            this.state = 156
            ws()

            this.state = 160
            errorHandler.sync(this)
            _la = _input.LA(1)

            if (_la == Tokens.INT) {
                this.state = 157
                end()

                this.state = 158
                ws()

            }
            this.state = 168
            errorHandler.sync(this)
            _la = _input.LA(1)

            if (_la == Tokens.COLON) {
                this.state = 162
                match(Tokens.COLON)

                this.state = 166
                errorHandler.sync(this)

                when (interpreter.adaptivePredict(_input, 8, context)) {
                    1 -> {
                        this.state = 163
                        ws()

                        this.state = 164
                        step()

                    }
                }
            }
        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class StartContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Start

        public fun int(): IntContext = getRuleContext(IntContext::class, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterStart(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitStart(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitStart(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun start(): StartContext {
        var _localctx = StartContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 20, Rules.Start)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 170
            int()

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class EndContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.End

        public fun int(): IntContext = getRuleContext(IntContext::class, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterEnd(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitEnd(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitEnd(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun end(): EndContext {
        var _localctx = EndContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 22, Rules.End)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 172
            int()

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class StepContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Step

        public fun int(): IntContext = getRuleContext(IntContext::class, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterStep(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitStep(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitStep(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun step(): StepContext {
        var _localctx = StepContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 24, Rules.Step)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 174
            int()

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Filter_queryContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Filter_query

        public fun rel_query(): Rel_queryContext? = getRuleContext(Rel_queryContext::class, 0)
        public fun jsonpath_query(): Jsonpath_queryContext? = getRuleContext(Jsonpath_queryContext::class, 0)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterFilter_query(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitFilter_query(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitFilter_query(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun filter_query(): Filter_queryContext {
        var _localctx = Filter_queryContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 26, Rules.Filter_query)

        try {
            this.state = 178
            errorHandler.sync(this)

            when (_input.LA(1)) {
                Tokens.CURRENT_NODE_IDENTIFIER -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 1)
                    this.state = 176
                    rel_query()

                }

                Tokens.ROOT_IDENTIFIER -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 2)
                    this.state = 177
                    jsonpath_query()

                }
                else -> throw NoViableAltException(this)
            }
        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Rel_queryContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Rel_query

        public fun currentNodeIdentifier(): CurrentNodeIdentifierContext = getRuleContext(
            CurrentNodeIdentifierContext::class, 0)!!
        public fun segments(): SegmentsContext = getRuleContext(SegmentsContext::class, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterRel_query(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitRel_query(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitRel_query(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun rel_query(): Rel_queryContext {
        var _localctx = Rel_queryContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 28, Rules.Rel_query)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 180
            currentNodeIdentifier()

            this.state = 181
            segments()

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Singular_queryContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Singular_query

        public fun rel_singular_query(): Rel_singular_queryContext? = getRuleContext(
            Rel_singular_queryContext::class, 0)
        public fun abs_singular_query(): Abs_singular_queryContext? = getRuleContext(
            Abs_singular_queryContext::class, 0)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterSingular_query(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitSingular_query(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitSingular_query(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun singular_query(): Singular_queryContext {
        var _localctx = Singular_queryContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 30, Rules.Singular_query)

        try {
            this.state = 185
            errorHandler.sync(this)

            when (_input.LA(1)) {
                Tokens.CURRENT_NODE_IDENTIFIER -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 1)
                    this.state = 183
                    rel_singular_query()

                }

                Tokens.ROOT_IDENTIFIER -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 2)
                    this.state = 184
                    abs_singular_query()

                }
                else -> throw NoViableAltException(this)
            }
        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Rel_singular_queryContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Rel_singular_query

        public fun currentNodeIdentifier(): CurrentNodeIdentifierContext = getRuleContext(
            CurrentNodeIdentifierContext::class, 0)!!
        public fun singular_query_segments(): Singular_query_segmentsContext = getRuleContext(
            Singular_query_segmentsContext::class, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterRel_singular_query(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitRel_singular_query(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitRel_singular_query(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun rel_singular_query(): Rel_singular_queryContext {
        var _localctx = Rel_singular_queryContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 32, Rules.Rel_singular_query)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 187
            currentNodeIdentifier()

            this.state = 188
            singular_query_segments()

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Abs_singular_queryContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Abs_singular_query

        public fun rootIdentifier(): RootIdentifierContext = getRuleContext(RootIdentifierContext::class, 0)!!
        public fun singular_query_segments(): Singular_query_segmentsContext = getRuleContext(
            Singular_query_segmentsContext::class, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterAbs_singular_query(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitAbs_singular_query(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitAbs_singular_query(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun abs_singular_query(): Abs_singular_queryContext {
        var _localctx = Abs_singular_queryContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 34, Rules.Abs_singular_query)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 190
            rootIdentifier()

            this.state = 191
            singular_query_segments()

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Singular_query_segmentsContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Singular_query_segments

        public fun ws(): List<WsContext> = getRuleContexts(WsContext::class)
        public fun ws(i: Int): WsContext? = getRuleContext(WsContext::class, i)
        public fun singular_query_segment(): List<Singular_query_segmentContext> = getRuleContexts(
            Singular_query_segmentContext::class)
        public fun singular_query_segment(i: Int): Singular_query_segmentContext? = getRuleContext(
            Singular_query_segmentContext::class, i)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterSingular_query_segments(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitSingular_query_segments(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitSingular_query_segments(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun singular_query_segments(): Singular_query_segmentsContext {
        var _localctx = Singular_query_segmentsContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 36, Rules.Singular_query_segments)

        try {
            var _alt: Int
            enterOuterAlt(_localctx, 1)
            this.state = 198
            errorHandler.sync(this)
            _alt = interpreter.adaptivePredict(_input, 12, context)

            while (_alt != 2 && _alt != INVALID_ALT_NUMBER) {
                if (_alt == 1 ) {
                    this.state = 193
                    ws()

                    this.state = 194
                    singular_query_segment()
             
                }

                this.state = 200
                errorHandler.sync(this)
                _alt = interpreter.adaptivePredict(_input, 12, context)
            }
        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Singular_query_segmentContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Singular_query_segment

        public fun name_segment(): Name_segmentContext? = getRuleContext(Name_segmentContext::class, 0)
        public fun index_segment(): Index_segmentContext? = getRuleContext(Index_segmentContext::class, 0)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterSingular_query_segment(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitSingular_query_segment(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitSingular_query_segment(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun singular_query_segment(): Singular_query_segmentContext {
        var _localctx = Singular_query_segmentContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 38, Rules.Singular_query_segment)

        try {
            this.state = 203
            errorHandler.sync(this)

            when (interpreter.adaptivePredict(_input, 13, context)) {
                1 -> {
                    enterOuterAlt(_localctx, 1)
                    this.state = 201
                    name_segment()

                }2 -> {
                    enterOuterAlt(_localctx, 2)
                    this.state = 202
                    index_segment()

                }
            }
        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Name_segmentContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Name_segment

        public fun SQUARE_BRACKET_OPEN(): TerminalNode? = getToken(Tokens.SQUARE_BRACKET_OPEN, 0)
        public fun name_selector(): Name_selectorContext? = getRuleContext(Name_selectorContext::class, 0)
        public fun SQUARE_BRACKET_CLOSE(): TerminalNode? = getToken(Tokens.SQUARE_BRACKET_CLOSE, 0)
        public fun SHORTHAND_SELECTOR(): TerminalNode? = getToken(Tokens.SHORTHAND_SELECTOR, 0)
        public fun memberNameShorthand(): MemberNameShorthandContext? = getRuleContext(
            MemberNameShorthandContext::class, 0)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterName_segment(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitName_segment(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitName_segment(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun name_segment(): Name_segmentContext {
        var _localctx = Name_segmentContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 40, Rules.Name_segment)

        try {
            this.state = 211
            errorHandler.sync(this)

            when (_input.LA(1)) {
                Tokens.SQUARE_BRACKET_OPEN -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 1)
                    this.state = 205
                    match(Tokens.SQUARE_BRACKET_OPEN)

                    this.state = 206
                    name_selector()

                    this.state = 207
                    match(Tokens.SQUARE_BRACKET_CLOSE)

                }

                Tokens.SHORTHAND_SELECTOR -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 2)
                    this.state = 209
                    match(Tokens.SHORTHAND_SELECTOR)

                    this.state = 210
                    memberNameShorthand()

                }
                else -> throw NoViableAltException(this)
            }
        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Index_segmentContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Index_segment

        public fun SQUARE_BRACKET_OPEN(): TerminalNode = getToken(Tokens.SQUARE_BRACKET_OPEN, 0)!!
        public fun index_selector(): Index_selectorContext = getRuleContext(Index_selectorContext::class, 0)!!
        public fun SQUARE_BRACKET_CLOSE(): TerminalNode = getToken(Tokens.SQUARE_BRACKET_CLOSE, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterIndex_segment(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitIndex_segment(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitIndex_segment(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun index_segment(): Index_segmentContext {
        var _localctx = Index_segmentContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 42, Rules.Index_segment)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 213
            match(Tokens.SQUARE_BRACKET_OPEN)

            this.state = 214
            index_selector()

            this.state = 215
            match(Tokens.SQUARE_BRACKET_CLOSE)

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Filter_selectorContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Filter_selector

        public fun QUESTIONMARK(): TerminalNode = getToken(Tokens.QUESTIONMARK, 0)!!
        public fun ws(): WsContext = getRuleContext(WsContext::class, 0)!!
        public fun logical_expr(): Logical_exprContext = getRuleContext(Logical_exprContext::class, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterFilter_selector(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitFilter_selector(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitFilter_selector(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun filter_selector(): Filter_selectorContext {
        var _localctx = Filter_selectorContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 44, Rules.Filter_selector)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 217
            match(Tokens.QUESTIONMARK)

            this.state = 218
            ws()

            this.state = 219
            logical_expr()

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Logical_exprContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Logical_expr

        public fun logical_or_expr(): Logical_or_exprContext = getRuleContext(Logical_or_exprContext::class, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterLogical_expr(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitLogical_expr(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitLogical_expr(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun logical_expr(): Logical_exprContext {
        var _localctx = Logical_exprContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 46, Rules.Logical_expr)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 221
            logical_or_expr()

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Logical_or_exprContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Logical_or_expr

        public fun logical_and_expr(): List<Logical_and_exprContext> = getRuleContexts(
            Logical_and_exprContext::class)
        public fun logical_and_expr(i: Int): Logical_and_exprContext? = getRuleContext(
            Logical_and_exprContext::class, i)
        public fun ws(): List<WsContext> = getRuleContexts(WsContext::class)
        public fun ws(i: Int): WsContext? = getRuleContext(WsContext::class, i)
        public fun LOGICAL_OR_OP(): List<TerminalNode> = getTokens(Tokens.LOGICAL_OR_OP)
        public fun LOGICAL_OR_OP(i: Int): TerminalNode? = getToken(Tokens.LOGICAL_OR_OP, i)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterLogical_or_expr(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitLogical_or_expr(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitLogical_or_expr(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun logical_or_expr(): Logical_or_exprContext {
        var _localctx = Logical_or_exprContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 48, Rules.Logical_or_expr)

        try {
            var _alt: Int
            enterOuterAlt(_localctx, 1)
            this.state = 223
            logical_and_expr()

            this.state = 231
            errorHandler.sync(this)
            _alt = interpreter.adaptivePredict(_input, 15, context)

            while (_alt != 2 && _alt != INVALID_ALT_NUMBER) {
                if (_alt == 1 ) {
                    this.state = 224
                    ws()

                    this.state = 225
                    match(Tokens.LOGICAL_OR_OP)

                    this.state = 226
                    ws()

                    this.state = 227
                    logical_and_expr()
             
                }

                this.state = 233
                errorHandler.sync(this)
                _alt = interpreter.adaptivePredict(_input, 15, context)
            }
        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Logical_and_exprContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Logical_and_expr

        public fun basic_expr(): List<Basic_exprContext> = getRuleContexts(Basic_exprContext::class)
        public fun basic_expr(i: Int): Basic_exprContext? = getRuleContext(Basic_exprContext::class, i)
        public fun ws(): List<WsContext> = getRuleContexts(WsContext::class)
        public fun ws(i: Int): WsContext? = getRuleContext(WsContext::class, i)
        public fun LOGICAL_AND_OP(): List<TerminalNode> = getTokens(Tokens.LOGICAL_AND_OP)
        public fun LOGICAL_AND_OP(i: Int): TerminalNode? = getToken(Tokens.LOGICAL_AND_OP, i)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterLogical_and_expr(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitLogical_and_expr(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitLogical_and_expr(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun logical_and_expr(): Logical_and_exprContext {
        var _localctx = Logical_and_exprContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 50, Rules.Logical_and_expr)

        try {
            var _alt: Int
            enterOuterAlt(_localctx, 1)
            this.state = 234
            basic_expr()

            this.state = 242
            errorHandler.sync(this)
            _alt = interpreter.adaptivePredict(_input, 16, context)

            while (_alt != 2 && _alt != INVALID_ALT_NUMBER) {
                if (_alt == 1 ) {
                    this.state = 235
                    ws()

                    this.state = 236
                    match(Tokens.LOGICAL_AND_OP)

                    this.state = 237
                    ws()

                    this.state = 238
                    basic_expr()
             
                }

                this.state = 244
                errorHandler.sync(this)
                _alt = interpreter.adaptivePredict(_input, 16, context)
            }
        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Basic_exprContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Basic_expr

        public fun paren_expr(): Paren_exprContext? = getRuleContext(Paren_exprContext::class, 0)
        public fun comparison_expr(): Comparison_exprContext? = getRuleContext(
            Comparison_exprContext::class, 0)
        public fun test_expr(): Test_exprContext? = getRuleContext(Test_exprContext::class, 0)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterBasic_expr(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitBasic_expr(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitBasic_expr(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun basic_expr(): Basic_exprContext {
        var _localctx = Basic_exprContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 52, Rules.Basic_expr)

        try {
            this.state = 248
            errorHandler.sync(this)

            when (interpreter.adaptivePredict(_input, 17, context)) {
                1 -> {
                    enterOuterAlt(_localctx, 1)
                    this.state = 245
                    paren_expr()

                }2 -> {
                    enterOuterAlt(_localctx, 2)
                    this.state = 246
                    comparison_expr()

                }3 -> {
                    enterOuterAlt(_localctx, 3)
                    this.state = 247
                    test_expr()

                }
            }
        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Paren_exprContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Paren_expr

        public fun BRACKET_OPEN(): TerminalNode = getToken(Tokens.BRACKET_OPEN, 0)!!
        public fun ws(): List<WsContext> = getRuleContexts(WsContext::class)
        public fun ws(i: Int): WsContext? = getRuleContext(WsContext::class, i)
        public fun logical_expr(): Logical_exprContext = getRuleContext(Logical_exprContext::class, 0)!!
        public fun BRACKET_CLOSE(): TerminalNode = getToken(Tokens.BRACKET_CLOSE, 0)!!
        public fun LOGICAL_NOT_OP(): TerminalNode? = getToken(Tokens.LOGICAL_NOT_OP, 0)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterParen_expr(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitParen_expr(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitParen_expr(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun paren_expr(): Paren_exprContext {
        var _localctx = Paren_exprContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 54, Rules.Paren_expr)
        var _la: Int

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 252
            errorHandler.sync(this)
            _la = _input.LA(1)

            if (_la == Tokens.LOGICAL_NOT_OP) {
                this.state = 250
                match(Tokens.LOGICAL_NOT_OP)

                this.state = 251
                ws()

            }
            this.state = 254
            match(Tokens.BRACKET_OPEN)

            this.state = 255
            ws()

            this.state = 256
            logical_expr()

            this.state = 257
            ws()

            this.state = 258
            match(Tokens.BRACKET_CLOSE)

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Test_exprContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Test_expr

        public fun filter_query(): Filter_queryContext? = getRuleContext(Filter_queryContext::class, 0)
        public fun function_expr(): Function_exprContext? = getRuleContext(Function_exprContext::class, 0)
        public fun LOGICAL_NOT_OP(): TerminalNode? = getToken(Tokens.LOGICAL_NOT_OP, 0)
        public fun ws(): WsContext? = getRuleContext(WsContext::class, 0)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterTest_expr(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitTest_expr(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitTest_expr(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun test_expr(): Test_exprContext {
        var _localctx = Test_exprContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 56, Rules.Test_expr)
        var _la: Int

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 262
            errorHandler.sync(this)
            _la = _input.LA(1)

            if (_la == Tokens.LOGICAL_NOT_OP) {
                this.state = 260
                match(Tokens.LOGICAL_NOT_OP)

                this.state = 261
                ws()

            }
            this.state = 266
            errorHandler.sync(this)

            when (_input.LA(1)) {
                Tokens.ROOT_IDENTIFIER, Tokens.CURRENT_NODE_IDENTIFIER -> /*LL1AltBlock*/ {
                    this.state = 264
                    filter_query()

                }

                Tokens.FUNCTION_NAME -> /*LL1AltBlock*/ {
                    this.state = 265
                    function_expr()

                }
                else -> throw NoViableAltException(this)
            }
        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Comparison_exprContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Comparison_expr

        public fun firstComparable(): FirstComparableContext = getRuleContext(FirstComparableContext::class, 0)!!
        public fun ws(): List<WsContext> = getRuleContexts(WsContext::class)
        public fun ws(i: Int): WsContext? = getRuleContext(WsContext::class, i)
        public fun comparisonOp(): ComparisonOpContext = getRuleContext(ComparisonOpContext::class, 0)!!
        public fun secondComparable(): SecondComparableContext = getRuleContext(
            SecondComparableContext::class, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterComparison_expr(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitComparison_expr(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitComparison_expr(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun comparison_expr(): Comparison_exprContext {
        var _localctx = Comparison_exprContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 58, Rules.Comparison_expr)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 268
            firstComparable()

            this.state = 269
            ws()

            this.state = 270
            comparisonOp()

            this.state = 271
            ws()

            this.state = 272
            secondComparable()

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class FirstComparableContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.FirstComparable

        public fun comparable(): ComparableContext = getRuleContext(ComparableContext::class, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterFirstComparable(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitFirstComparable(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitFirstComparable(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun firstComparable(): FirstComparableContext {
        var _localctx = FirstComparableContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 60, Rules.FirstComparable)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 274
            comparable()

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class SecondComparableContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.SecondComparable

        public fun comparable(): ComparableContext = getRuleContext(ComparableContext::class, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterSecondComparable(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitSecondComparable(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitSecondComparable(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun secondComparable(): SecondComparableContext {
        var _localctx = SecondComparableContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 62, Rules.SecondComparable)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 276
            comparable()

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class LiteralContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Literal

        public fun int(): IntContext? = getRuleContext(IntContext::class, 0)
        public fun number(): NumberContext? = getRuleContext(NumberContext::class, 0)
        public fun stringLiteral(): StringLiteralContext? = getRuleContext(StringLiteralContext::class, 0)
        public fun true_(): TrueContext? = getRuleContext(TrueContext::class, 0)
        public fun false_(): FalseContext? = getRuleContext(FalseContext::class, 0)
        public fun null_(): NullContext? = getRuleContext(NullContext::class, 0)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterLiteral(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitLiteral(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitLiteral(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun literal(): LiteralContext {
        var _localctx = LiteralContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 64, Rules.Literal)

        try {
            this.state = 284
            errorHandler.sync(this)

            when (_input.LA(1)) {
                Tokens.INT -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 1)
                    this.state = 278
                    int()

                }

                Tokens.NUMBER -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 2)
                    this.state = 279
                    number()

                }

                Tokens.STRING_LITERAL -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 3)
                    this.state = 280
                    stringLiteral()

                }

                Tokens.TRUE -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 4)
                    this.state = 281
                    true_()

                }

                Tokens.FALSE -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 5)
                    this.state = 282
                    false_()

                }

                Tokens.NULL -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 6)
                    this.state = 283
                    null_()

                }
                else -> throw NoViableAltException(this)
            }
        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class ComparableContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Comparable

        public fun literal(): LiteralContext? = getRuleContext(LiteralContext::class, 0)
        public fun singular_query(): Singular_queryContext? = getRuleContext(Singular_queryContext::class, 0)
        public fun function_expr(): Function_exprContext? = getRuleContext(Function_exprContext::class, 0)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterComparable(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitComparable(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitComparable(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun comparable(): ComparableContext {
        var _localctx = ComparableContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 66, Rules.Comparable)

        try {
            this.state = 289
            errorHandler.sync(this)

            when (_input.LA(1)) {
                Tokens.STRING_LITERAL, Tokens.NULL, Tokens.TRUE, Tokens.FALSE, Tokens.INT, Tokens.NUMBER -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 1)
                    this.state = 286
                    literal()

                }

                Tokens.ROOT_IDENTIFIER, Tokens.CURRENT_NODE_IDENTIFIER -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 2)
                    this.state = 287
                    singular_query()

                }

                Tokens.FUNCTION_NAME -> /*LL1AltBlock*/ {
                    enterOuterAlt(_localctx, 3)
                    this.state = 288
                    function_expr()

                }
                else -> throw NoViableAltException(this)
            }
        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Function_exprContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Function_expr

        public fun FUNCTION_NAME(): TerminalNode = getToken(Tokens.FUNCTION_NAME, 0)!!
        public fun BRACKET_OPEN(): TerminalNode = getToken(Tokens.BRACKET_OPEN, 0)!!
        public fun ws(): List<WsContext> = getRuleContexts(WsContext::class)
        public fun ws(i: Int): WsContext? = getRuleContext(WsContext::class, i)
        public fun BRACKET_CLOSE(): TerminalNode = getToken(Tokens.BRACKET_CLOSE, 0)!!
        public fun function_argument(): List<Function_argumentContext> = getRuleContexts(
            Function_argumentContext::class)
        public fun function_argument(i: Int): Function_argumentContext? = getRuleContext(
            Function_argumentContext::class, i)
        public fun COMMA(): List<TerminalNode> = getTokens(Tokens.COMMA)
        public fun COMMA(i: Int): TerminalNode? = getToken(Tokens.COMMA, i)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterFunction_expr(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitFunction_expr(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitFunction_expr(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun function_expr(): Function_exprContext {
        var _localctx = Function_exprContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 68, Rules.Function_expr)
        var _la: Int

        try {
            var _alt: Int
            enterOuterAlt(_localctx, 1)
            this.state = 291
            match(Tokens.FUNCTION_NAME)

            this.state = 292
            match(Tokens.BRACKET_OPEN)

            this.state = 293
            ws()

            this.state = 305
            errorHandler.sync(this)
            _la = _input.LA(1)

            if ((((_la) and 0x3f.inv()) == 0 && ((1L shl _la) and 1065373702L) != 0L)) {
                this.state = 294
                function_argument()

                this.state = 302
                errorHandler.sync(this)
                _alt = interpreter.adaptivePredict(_input, 23, context)

                while (_alt != 2 && _alt != INVALID_ALT_NUMBER) {
                    if (_alt == 1 ) {
                        this.state = 295
                        ws()

                        this.state = 296
                        match(Tokens.COMMA)

                        this.state = 297
                        ws()

                        this.state = 298
                        function_argument()
                 
                    }

                    this.state = 304
                    errorHandler.sync(this)
                    _alt = interpreter.adaptivePredict(_input, 23, context)
                }
            }
            this.state = 307
            ws()

            this.state = 308
            match(Tokens.BRACKET_CLOSE)

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class Function_argumentContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Function_argument

        public fun literal(): LiteralContext? = getRuleContext(LiteralContext::class, 0)
        public fun filter_query(): Filter_queryContext? = getRuleContext(Filter_queryContext::class, 0)
        public fun function_expr(): Function_exprContext? = getRuleContext(Function_exprContext::class, 0)
        public fun logical_expr(): Logical_exprContext? = getRuleContext(Logical_exprContext::class, 0)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterFunction_argument(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitFunction_argument(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitFunction_argument(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun function_argument(): Function_argumentContext {
        var _localctx = Function_argumentContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 70, Rules.Function_argument)

        try {
            this.state = 314
            errorHandler.sync(this)

            when (interpreter.adaptivePredict(_input, 25, context)) {
                1 -> {
                    enterOuterAlt(_localctx, 1)
                    this.state = 310
                    literal()

                }2 -> {
                    enterOuterAlt(_localctx, 2)
                    this.state = 311
                    filter_query()

                }3 -> {
                    enterOuterAlt(_localctx, 3)
                    this.state = 312
                    function_expr()

                }4 -> {
                    enterOuterAlt(_localctx, 4)
                    this.state = 313
                    logical_expr()

                }
            }
        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class RootIdentifierContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.RootIdentifier

        public fun ROOT_IDENTIFIER(): TerminalNode = getToken(Tokens.ROOT_IDENTIFIER, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterRootIdentifier(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitRootIdentifier(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitRootIdentifier(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun rootIdentifier(): RootIdentifierContext {
        var _localctx = RootIdentifierContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 72, Rules.RootIdentifier)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 316
            match(Tokens.ROOT_IDENTIFIER)

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class CurrentNodeIdentifierContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.CurrentNodeIdentifier

        public fun CURRENT_NODE_IDENTIFIER(): TerminalNode = getToken(Tokens.CURRENT_NODE_IDENTIFIER, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterCurrentNodeIdentifier(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitCurrentNodeIdentifier(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitCurrentNodeIdentifier(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun currentNodeIdentifier(): CurrentNodeIdentifierContext {
        var _localctx = CurrentNodeIdentifierContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 74, Rules.CurrentNodeIdentifier)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 318
            match(Tokens.CURRENT_NODE_IDENTIFIER)

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class WsContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Ws

        public fun BLANK(): List<TerminalNode> = getTokens(Tokens.BLANK)
        public fun BLANK(i: Int): TerminalNode? = getToken(Tokens.BLANK, i)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterWs(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitWs(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitWs(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun ws(): WsContext {
        var _localctx = WsContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 76, Rules.Ws)

        try {
            var _alt: Int
            enterOuterAlt(_localctx, 1)
            this.state = 323
            errorHandler.sync(this)
            _alt = interpreter.adaptivePredict(_input, 26, context)

            while (_alt != 2 && _alt != INVALID_ALT_NUMBER) {
                if (_alt == 1 ) {
                    this.state = 320
                    match(Tokens.BLANK)
             
                }

                this.state = 325
                errorHandler.sync(this)
                _alt = interpreter.adaptivePredict(_input, 26, context)
            }
        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class WildcardSelectorContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.WildcardSelector

        public fun WILDCARD_SELECTOR(): TerminalNode = getToken(Tokens.WILDCARD_SELECTOR, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterWildcardSelector(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitWildcardSelector(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitWildcardSelector(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun wildcardSelector(): WildcardSelectorContext {
        var _localctx = WildcardSelectorContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 78, Rules.WildcardSelector)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 326
            match(Tokens.WILDCARD_SELECTOR)

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class MemberNameShorthandContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.MemberNameShorthand

        public fun MEMBER_NAME_SHORTHAND(): TerminalNode = getToken(Tokens.MEMBER_NAME_SHORTHAND, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterMemberNameShorthand(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitMemberNameShorthand(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitMemberNameShorthand(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun memberNameShorthand(): MemberNameShorthandContext {
        var _localctx = MemberNameShorthandContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 80, Rules.MemberNameShorthand)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 328
            match(Tokens.MEMBER_NAME_SHORTHAND)

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class StringLiteralContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.StringLiteral

        public fun STRING_LITERAL(): TerminalNode = getToken(Tokens.STRING_LITERAL, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterStringLiteral(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitStringLiteral(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitStringLiteral(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun stringLiteral(): StringLiteralContext {
        var _localctx = StringLiteralContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 82, Rules.StringLiteral)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 330
            match(Tokens.STRING_LITERAL)

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class NumberContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Number

        public fun NUMBER(): TerminalNode = getToken(Tokens.NUMBER, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterNumber(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitNumber(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitNumber(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun number(): NumberContext {
        var _localctx = NumberContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 84, Rules.Number)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 332
            match(Tokens.NUMBER)

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class IntContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Int

        public fun INT(): TerminalNode = getToken(Tokens.INT, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterInt(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitInt(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitInt(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun int(): IntContext {
        var _localctx = IntContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 86, Rules.Int)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 334
            match(Tokens.INT)

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class TrueContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.True

        public fun TRUE(): TerminalNode = getToken(Tokens.TRUE, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterTrue(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitTrue(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitTrue(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun true_(): TrueContext {
        var _localctx = TrueContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 88, Rules.True)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 336
            match(Tokens.TRUE)

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class FalseContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.False

        public fun FALSE(): TerminalNode = getToken(Tokens.FALSE, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterFalse(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitFalse(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitFalse(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun false_(): FalseContext {
        var _localctx = FalseContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 90, Rules.False)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 338
            match(Tokens.FALSE)

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class NullContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.Null

        public fun NULL(): TerminalNode = getToken(Tokens.NULL, 0)!!

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterNull(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitNull(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitNull(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun null_(): NullContext {
        var _localctx = NullContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 92, Rules.Null)

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 340
            match(Tokens.NULL)

        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }

    public open class ComparisonOpContext : ParserRuleContext {
        override val ruleIndex: Int = Rules.ComparisonOp

        public fun COMPARISON_OP_EQUALS(): TerminalNode? = getToken(Tokens.COMPARISON_OP_EQUALS, 0)
        public fun COMPARISON_OP_NOT_EQUALS(): TerminalNode? = getToken(Tokens.COMPARISON_OP_NOT_EQUALS, 0)
        public fun COMPARISON_OP_SMALLER_THAN(): TerminalNode? = getToken(Tokens.COMPARISON_OP_SMALLER_THAN, 0)
        public fun COMPARISON_OP_GREATER_THAN(): TerminalNode? = getToken(Tokens.COMPARISON_OP_GREATER_THAN, 0)
        public fun COMPARISON_OP_SMALLER_THAN_OR_EQUALS(): TerminalNode? = getToken(Tokens.COMPARISON_OP_SMALLER_THAN_OR_EQUALS, 0)
        public fun COMPARISON_OP_GREATER_THAN_OR_EQUALS(): TerminalNode? = getToken(Tokens.COMPARISON_OP_GREATER_THAN_OR_EQUALS, 0)

        public constructor(parent: ParserRuleContext?, invokingState: Int) : super(parent, invokingState) {
        }

        override fun enterRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.enterComparisonOp(this)
            }
        }

        override fun exitRule(listener: ParseTreeListener) {
            if (listener is JsonPathParserListener) {
                listener.exitComparisonOp(this)
            }
        }

        override fun <T> accept(visitor: ParseTreeVisitor<out T>): T {
            return if (visitor is JsonPathParserVisitor) {
                visitor.visitComparisonOp(this)
            } else {
                visitor.visitChildren(this)!!
            }
        }
    }


    public fun comparisonOp(): ComparisonOpContext {
        var _localctx = ComparisonOpContext(context, state)
        var _token: Token?
        var _ctx: RuleContext?

        enterRule(_localctx, 94, Rules.ComparisonOp)
        var _la: Int

        try {
            enterOuterAlt(_localctx, 1)
            this.state = 342
            _la = _input.LA(1)

            if (!((((_la) and 0x3f.inv()) == 0 && ((1L shl _la) and 8257536L) != 0L))) {
                errorHandler.recoverInline(this)
            }
            else {
                if (_input.LA(1) == Tokens.EOF) {
                    isMatchedEOF = true
                }

                errorHandler.reportMatch(this)
                consume()
            }
        }
        catch (re: RecognitionException) {
            _localctx.exception = re
            errorHandler.reportError(this, re)
            errorHandler.recover(this, re)
        }
        finally {
            exitRule()
        }

        return _localctx
    }
}

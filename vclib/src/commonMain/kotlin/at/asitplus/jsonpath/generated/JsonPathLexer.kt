// Generated from C:/Users/stefan.kreiner/Documents/git/com.github/a-sit-plus/jsonpath/jsonpath/build/processedResources/iosArm64/main/grammar/JsonPathLexer.g4 by ANTLR 4.13.1
package at.asitplus.jsonpath.generated

import org.antlr.v4.kotlinruntime.CharStream
import org.antlr.v4.kotlinruntime.Lexer
import org.antlr.v4.kotlinruntime.RuntimeMetaData
import org.antlr.v4.kotlinruntime.Vocabulary
import org.antlr.v4.kotlinruntime.VocabularyImpl
import org.antlr.v4.kotlinruntime.atn.ATN
import org.antlr.v4.kotlinruntime.atn.ATNDeserializer
import org.antlr.v4.kotlinruntime.atn.LexerATNSimulator
import org.antlr.v4.kotlinruntime.atn.PredictionContextCache
import org.antlr.v4.kotlinruntime.dfa.DFA

@Suppress(
    "ClassName",
    "FunctionName",
    "LocalVariableName",
    "ConstPropertyName",
)
public open class JsonPathLexer(input: CharStream) : Lexer(input) {
    private companion object {
        init {
            RuntimeMetaData.checkVersion("4.13.1", RuntimeMetaData.runtimeVersion)
        }

        private const val SERIALIZED_ATN: String =
            "\u0004\u0000\u001e\u01d6\u0006\uffff\uffff\u0006\uffff\uffff\u0002\u0000\u0007\u0000\u0002\u0001\u0007\u0001\u0002\u0002\u0007\u0002\u0002\u0003\u0007\u0003\u0002\u0004\u0007\u0004\u0002\u0005\u0007\u0005\u0002\u0006\u0007\u0006\u0002\u0007\u0007\u0007\u0002\u0008\u0007\u0008\u0002\u0009\u0007\u0009\u0002\u000a\u0007\u000a\u0002\u000b\u0007\u000b\u0002\u000c\u0007\u000c\u0002\u000d\u0007\u000d\u0002\u000e\u0007\u000e\u0002\u000f\u0007\u000f\u0002\u0010\u0007\u0010\u0002\u0011\u0007\u0011\u0002\u0012\u0007\u0012\u0002\u0013\u0007\u0013\u0002\u0014\u0007\u0014\u0002\u0015\u0007\u0015\u0002\u0016\u0007\u0016\u0002\u0017\u0007\u0017\u0002\u0018\u0007\u0018\u0002\u0019\u0007\u0019\u0002\u001a\u0007\u001a\u0002\u001b\u0007\u001b\u0002\u001c\u0007\u001c\u0002\u001d\u0007\u001d\u0002\u001e\u0007\u001e\u0002\u001f\u0007\u001f\u0002\u0020\u0007\u0020\u0002\u0021\u0007\u0021\u0002\u0022\u0007\u0022\u0002\u0023\u0007\u0023\u0002\u0024\u0007\u0024\u0002\u0025\u0007\u0025\u0002\u0026\u0007\u0026\u0002\u0027\u0007\u0027\u0002\u0028\u0007\u0028\u0002\u0029\u0007\u0029\u0002\u002a\u0007\u002a\u0002\u002b\u0007\u002b\u0002\u002c\u0007\u002c\u0002\u002d\u0007\u002d\u0002\u002e\u0007\u002e\u0002\u002f\u0007\u002f\u0002\u0030\u0007\u0030\u0002\u0031\u0007\u0031\u0002\u0032\u0007\u0032\u0002\u0033\u0007\u0033\u0002\u0034\u0007\u0034\u0002\u0035\u0007\u0035\u0002\u0036\u0007\u0036\u0002\u0037\u0007\u0037\u0002\u0038\u0007\u0038\u0002\u0039\u0007\u0039\u0002\u003a\u0007\u003a\u0002\u003b\u0007\u003b\u0002\u003c\u0007\u003c\u0002\u003d\u0007\u003d\u0002\u003e\u0007\u003e\u0002\u003f\u0007\u003f\u0002\u0040\u0007\u0040\u0002\u0041\u0007\u0041\u0002\u0042\u0007\u0042\u0002\u0043\u0007\u0043\u0002\u0044\u0007\u0044\u0002\u0045\u0007\u0045\u0002\u0046\u0007\u0046\u0002\u0047\u0007\u0047\u0002\u0048\u0007\u0048\u0002\u0049\u0007\u0049\u0002\u004a\u0007\u004a\u0002\u004b\u0007\u004b\u0001\u0000\u0001\u0000\u0001\u0001\u0001\u0001\u0001\u0002\u0001\u0002\u0001\u0003\u0001\u0003\u0001\u0003\u0001\u0003\u0001\u0003\u0001\u0004\u0001\u0004\u0001\u0004\u0001\u0004\u0001\u0005\u0001\u0005\u0001\u0006\u0001\u0006\u0001\u0007\u0001\u0007\u0001\u0008\u0001\u0008\u0001\u0009\u0001\u0009\u0001\u000a\u0001\u000a\u0001\u000b\u0001\u000b\u0001\u000c\u0001\u000c\u0001\u000d\u0001\u000d\u0001\u000e\u0001\u000e\u0001\u000e\u0001\u000f\u0001\u000f\u0001\u000f\u0001\u0010\u0001\u0010\u0001\u0010\u0001\u0011\u0001\u0011\u0001\u0011\u0001\u0012\u0001\u0012\u0001\u0013\u0001\u0013\u0001\u0014\u0001\u0014\u0001\u0014\u0001\u0015\u0001\u0015\u0001\u0015\u0001\u0016\u0001\u0016\u0001\u0017\u0001\u0017\u0001\u0017\u0001\u0017\u0001\u0017\u0001\u0018\u0001\u0018\u0001\u0018\u0001\u0018\u0001\u0018\u0001\u0019\u0001\u0019\u0001\u0019\u0001\u0019\u0001\u0019\u0001\u0019\u0001\u001a\u0001\u001a\u0001\u001b\u0001\u001b\u0003\u001b\u00e8\u0008\u001b\u0001\u001b\u0003\u001b\u00eb\u0008\u001b\u0001\u001b\u0003\u001b\u00ee\u0008\u001b\u0001\u001c\u0001\u001c\u0001\u001d\u0001\u001d\u0001\u001e\u0001\u001e\u0001\u001f\u0001\u001f\u0001\u0020\u0001\u0020\u0003\u0020\u00fa\u0008\u0020\u0001\u0021\u0001\u0021\u0003\u0021\u00fe\u0008\u0021\u0001\u0021\u0001\u0021\u0005\u0021\u0102\u0008\u0021\u000a\u0021\u000c\u0021\u0105\u0009\u0021\u0003\u0021\u0107\u0008\u0021\u0001\u0022\u0001\u0022\u0001\u0023\u0001\u0023\u0001\u0024\u0001\u0024\u0001\u0025\u0001\u0025\u0001\u0026\u0001\u0026\u0001\u0027\u0001\u0027\u0001\u0028\u0001\u0028\u0001\u0028\u0001\u0028\u0001\u0028\u0001\u0028\u0001\u0028\u0003\u0028\u011c\u0008\u0028\u0001\u0029\u0001\u0029\u0001\u0029\u0001\u0029\u0003\u0029\u0122\u0008\u0029\u0001\u0029\u0001\u0029\u0001\u0029\u0001\u002a\u0001\u002a\u0001\u002a\u0001\u002a\u0001\u002a\u0003\u002a\u012c\u0008\u002a\u0001\u002a\u0001\u002a\u0001\u002a\u0001\u002b\u0001\u002b\u0001\u002b\u0001\u002b\u0001\u002b\u0001\u002b\u0003\u002b\u0137\u0008\u002b\u0001\u002b\u0001\u002b\u0001\u002b\u0001\u002b\u0001\u002b\u0001\u002b\u0001\u002b\u0001\u002b\u0001\u002b\u0003\u002b\u0142\u0008\u002b\u0001\u002c\u0001\u002c\u0001\u002c\u0001\u002c\u0001\u002c\u0001\u002c\u0003\u002c\u014a\u0008\u002c\u0001\u002d\u0001\u002d\u0001\u002e\u0001\u002e\u0001\u002f\u0001\u002f\u0003\u002f\u0152\u0008\u002f\u0001\u0030\u0001\u0030\u0001\u0031\u0001\u0031\u0001\u0032\u0001\u0032\u0001\u0033\u0001\u0033\u0001\u0034\u0001\u0034\u0001\u0035\u0001\u0035\u0001\u0036\u0001\u0036\u0001\u0036\u0003\u0036\u0163\u0008\u0036\u0001\u0037\u0001\u0037\u0003\u0037\u0167\u0008\u0037\u0001\u0038\u0001\u0038\u0005\u0038\u016b\u0008\u0038\u000a\u0038\u000c\u0038\u016e\u0009\u0038\u0001\u0039\u0001\u0039\u0001\u0039\u0001\u0039\u0003\u0039\u0174\u0008\u0039\u0001\u003a\u0001\u003a\u0001\u003b\u0001\u003b\u0001\u003c\u0001\u003c\u0001\u003d\u0001\u003d\u0001\u003e\u0001\u003e\u0001\u003e\u0001\u003e\u0001\u003e\u0001\u003e\u0001\u003e\u0001\u003e\u0003\u003e\u0186\u0008\u003e\u0001\u003f\u0001\u003f\u0001\u003f\u0001\u003f\u0001\u003f\u0001\u003f\u0001\u003f\u0001\u003f\u0003\u003f\u0190\u0008\u003f\u0001\u0040\u0001\u0040\u0005\u0040\u0194\u0008\u0040\u000a\u0040\u000c\u0040\u0197\u0009\u0040\u0001\u0040\u0001\u0040\u0001\u0040\u0001\u0040\u0005\u0040\u019d\u0008\u0040\u000a\u0040\u000c\u0040\u01a0\u0009\u0040\u0001\u0040\u0001\u0040\u0003\u0040\u01a4\u0008\u0040\u0001\u0041\u0001\u0041\u0001\u0042\u0001\u0042\u0001\u0042\u0003\u0042\u01ab\u0008\u0042\u0001\u0043\u0001\u0043\u0005\u0043\u01af\u0008\u0043\u000a\u0043\u000c\u0043\u01b2\u0009\u0043\u0001\u0044\u0001\u0044\u0001\u0044\u0001\u0045\u0004\u0045\u01b8\u0008\u0045\u000b\u0045\u000c\u0045\u01b9\u0001\u0046\u0001\u0046\u0001\u0046\u0001\u0047\u0001\u0047\u0003\u0047\u01c1\u0008\u0047\u0001\u0048\u0001\u0048\u0003\u0048\u01c5\u0008\u0048\u0001\u0048\u0001\u0048\u0001\u0049\u0001\u0049\u0001\u0049\u0001\u0049\u0001\u004a\u0001\u004a\u0001\u004a\u0001\u004a\u0001\u004a\u0001\u004b\u0001\u004b\u0001\u004b\u0001\u004b\u0001\u004b\u0000\u0000\u004c\u0002\u0001\u0004\u0002\u0006\u0003\u0008\u0004\u000a\u0005\u000c\u0006\u000e\u0007\u0010\u0008\u0012\u0009\u0014\u000a\u0016\u000b\u0018\u000c\u001a\u000d\u001c\u000e\u001e\u000f\u0020\u0010\u0022\u0011\u0024\u0012\u0026\u0013\u0028\u0014\u002a\u0015\u002c\u0016\u002e\u0017\u0030\u0018\u0032\u0019\u0034\u001a\u0036\u001b\u0038\u001c\u003a\u001d\u003c\u0000\u003e\u0000\u0040\u0000\u0042\u0000\u0044\u0000\u0046\u0000\u0048\u0000\u004a\u0000\u004c\u0000\u004e\u0000\u0050\u0000\u0052\u0000\u0054\u0000\u0056\u0000\u0058\u0000\u005a\u0000\u005c\u0000\u005e\u0000\u0060\u0000\u0062\u0000\u0064\u0000\u0066\u0000\u0068\u0000\u006a\u0000\u006c\u0000\u006e\u0000\u0070\u0000\u0072\u0000\u0074\u0000\u0076\u0000\u0078\u0000\u007a\u0000\u007c\u0000\u007e\u0000\u0080\u0000\u0082\u0000\u0084\u0000\u0086\u0000\u0088\u0000\u008a\u0000\u008c\u0000\u008e\u0000\u0090\u0000\u0092\u0000\u0094\u001e\u0096\u0000\u0098\u0000\u0002\u0000\u0001\u000c\u0003\u0000\u0009\u000a\u000d\u000d\u0020\u0020\u0002\u0000\u0041\u0041\u0061\u0061\u0002\u0000\u0042\u0042\u0062\u0062\u0002\u0000\u0043\u0043\u0063\u0063\u0002\u0000\u0044\u0044\u0064\u0064\u0002\u0000\u0045\u0045\u0065\u0065\u0002\u0000\u0046\u0046\u0066\u0066\u0001\u0000\u0061\u007a\u0001\u0000\u0041\u005a\u0002\u0000\u0080\u8000\ud7ff\u8000\ue000\u8000\uffff\u0006\u0000\u002f\u002f\u0062\u0062\u0066\u0066\u006e\u006e\u0072\u0072\u0074\u0074\u0005\u0000\u0020\u0021\u0023\u0026\u0028\u005b\u005d\u8000\ud7ff\u8000\ue000\u8000\uffff\u01d7\u0000\u0002\u0001\u0000\u0000\u0000\u0000\u0004\u0001\u0000\u0000\u0000\u0000\u0006\u0001\u0000\u0000\u0000\u0000\u0008\u0001\u0000\u0000\u0000\u0000\u000a\u0001\u0000\u0000\u0000\u0000\u000c\u0001\u0000\u0000\u0000\u0000\u000e\u0001\u0000\u0000\u0000\u0000\u0010\u0001\u0000\u0000\u0000\u0000\u0012\u0001\u0000\u0000\u0000\u0000\u0014\u0001\u0000\u0000\u0000\u0000\u0016\u0001\u0000\u0000\u0000\u0000\u0018\u0001\u0000\u0000\u0000\u0000\u001a\u0001\u0000\u0000\u0000\u0000\u001c\u0001\u0000\u0000\u0000\u0000\u001e\u0001\u0000\u0000\u0000\u0000\u0020\u0001\u0000\u0000\u0000\u0000\u0022\u0001\u0000\u0000\u0000\u0000\u0024\u0001\u0000\u0000\u0000\u0000\u0026\u0001\u0000\u0000\u0000\u0000\u0028\u0001\u0000\u0000\u0000\u0000\u002a\u0001\u0000\u0000\u0000\u0000\u002c\u0001\u0000\u0000\u0000\u0000\u002e\u0001\u0000\u0000\u0000\u0000\u0030\u0001\u0000\u0000\u0000\u0000\u0032\u0001\u0000\u0000\u0000\u0000\u0034\u0001\u0000\u0000\u0000\u0000\u0036\u0001\u0000\u0000\u0000\u0000\u0038\u0001\u0000\u0000\u0000\u0000\u003a\u0001\u0000\u0000\u0000\u0001\u0094\u0001\u0000\u0000\u0000\u0001\u0096\u0001\u0000\u0000\u0000\u0001\u0098\u0001\u0000\u0000\u0000\u0002\u009a\u0001\u0000\u0000\u0000\u0004\u009c\u0001\u0000\u0000\u0000\u0006\u009e\u0001\u0000\u0000\u0000\u0008\u00a0\u0001\u0000\u0000\u0000\u000a\u00a5\u0001\u0000\u0000\u0000\u000c\u00a9\u0001\u0000\u0000\u0000\u000e\u00ab\u0001\u0000\u0000\u0000\u0010\u00ad\u0001\u0000\u0000\u0000\u0012\u00af\u0001\u0000\u0000\u0000\u0014\u00b1\u0001\u0000\u0000\u0000\u0016\u00b3\u0001\u0000\u0000\u0000\u0018\u00b5\u0001\u0000\u0000\u0000\u001a\u00b7\u0001\u0000\u0000\u0000\u001c\u00b9\u0001\u0000\u0000\u0000\u001e\u00bb\u0001\u0000\u0000\u0000\u0020\u00be\u0001\u0000\u0000\u0000\u0022\u00c1\u0001\u0000\u0000\u0000\u0024\u00c4\u0001\u0000\u0000\u0000\u0026\u00c7\u0001\u0000\u0000\u0000\u0028\u00c9\u0001\u0000\u0000\u0000\u002a\u00cb\u0001\u0000\u0000\u0000\u002c\u00ce\u0001\u0000\u0000\u0000\u002e\u00d1\u0001\u0000\u0000\u0000\u0030\u00d3\u0001\u0000\u0000\u0000\u0032\u00d8\u0001\u0000\u0000\u0000\u0034\u00dd\u0001\u0000\u0000\u0000\u0036\u00e3\u0001\u0000\u0000\u0000\u0038\u00e7\u0001\u0000\u0000\u0000\u003a\u00ef\u0001\u0000\u0000\u0000\u003c\u00f1\u0001\u0000\u0000\u0000\u003e\u00f3\u0001\u0000\u0000\u0000\u0040\u00f5\u0001\u0000\u0000\u0000\u0042\u00f9\u0001\u0000\u0000\u0000\u0044\u0106\u0001\u0000\u0000\u0000\u0046\u0108\u0001\u0000\u0000\u0000\u0048\u010a\u0001\u0000\u0000\u0000\u004a\u010c\u0001\u0000\u0000\u0000\u004c\u010e\u0001\u0000\u0000\u0000\u004e\u0110\u0001\u0000\u0000\u0000\u0050\u0112\u0001\u0000\u0000\u0000\u0052\u011b\u0001\u0000\u0000\u0000\u0054\u011d\u0001\u0000\u0000\u0000\u0056\u0126\u0001\u0000\u0000\u0000\u0058\u0141\u0001\u0000\u0000\u0000\u005a\u0149\u0001\u0000\u0000\u0000\u005c\u014b\u0001\u0000\u0000\u0000\u005e\u014d\u0001\u0000\u0000\u0000\u0060\u0151\u0001\u0000\u0000\u0000\u0062\u0153\u0001\u0000\u0000\u0000\u0064\u0155\u0001\u0000\u0000\u0000\u0066\u0157\u0001\u0000\u0000\u0000\u0068\u0159\u0001\u0000\u0000\u0000\u006a\u015b\u0001\u0000\u0000\u0000\u006c\u015d\u0001\u0000\u0000\u0000\u006e\u0162\u0001\u0000\u0000\u0000\u0070\u0166\u0001\u0000\u0000\u0000\u0072\u0168\u0001\u0000\u0000\u0000\u0074\u0173\u0001\u0000\u0000\u0000\u0076\u0175\u0001\u0000\u0000\u0000\u0078\u0177\u0001\u0000\u0000\u0000\u007a\u0179\u0001\u0000\u0000\u0000\u007c\u017b\u0001\u0000\u0000\u0000\u007e\u0185\u0001\u0000\u0000\u0000\u0080\u018f\u0001\u0000\u0000\u0000\u0082\u01a3\u0001\u0000\u0000\u0000\u0084\u01a5\u0001\u0000\u0000\u0000\u0086\u01aa\u0001\u0000\u0000\u0000\u0088\u01ac\u0001\u0000\u0000\u0000\u008a\u01b3\u0001\u0000\u0000\u0000\u008c\u01b7\u0001\u0000\u0000\u0000\u008e\u01bb\u0001\u0000\u0000\u0000\u0090\u01c0\u0001\u0000\u0000\u0000\u0092\u01c2\u0001\u0000\u0000\u0000\u0094\u01c8\u0001\u0000\u0000\u0000\u0096\u01cc\u0001\u0000\u0000\u0000\u0098\u01d1\u0001\u0000\u0000\u0000\u009a\u009b\u0005\u0024\u0000\u0000\u009b\u0003\u0001\u0000\u0000\u0000\u009c\u009d\u0005\u0040\u0000\u0000\u009d\u0005\u0001\u0000\u0000\u0000\u009e\u009f\u0003\u003c\u001d\u0000\u009f\u0007\u0001\u0000\u0000\u0000\u00a0\u00a1\u0005\u002e\u0000\u0000\u00a1\u00a2\u0005\u002e\u0000\u0000\u00a2\u00a3\u0001\u0000\u0000\u0000\u00a3\u00a4\u0006\u0003\u0000\u0000\u00a4\u0009\u0001\u0000\u0000\u0000\u00a5\u00a6\u0005\u002e\u0000\u0000\u00a6\u00a7\u0001\u0000\u0000\u0000\u00a7\u00a8\u0006\u0004\u0000\u0000\u00a8\u000b\u0001\u0000\u0000\u0000\u00a9\u00aa\u0003\u0062\u0030\u0000\u00aa\u000d\u0001\u0000\u0000\u0000\u00ab\u00ac\u0005\u003a\u0000\u0000\u00ac\u000f\u0001\u0000\u0000\u0000\u00ad\u00ae\u0005\u002c\u0000\u0000\u00ae\u0011\u0001\u0000\u0000\u0000\u00af\u00b0\u0003\u0064\u0031\u0000\u00b0\u0013\u0001\u0000\u0000\u0000\u00b1\u00b2\u0005\u005d\u0000\u0000\u00b2\u0015\u0001\u0000\u0000\u0000\u00b3\u00b4\u0005\u003f\u0000\u0000\u00b4\u0017\u0001\u0000\u0000\u0000\u00b5\u00b6\u0005\u0028\u0000\u0000\u00b6\u0019\u0001\u0000\u0000\u0000\u00b7\u00b8\u0005\u0029\u0000\u0000\u00b8\u001b\u0001\u0000\u0000\u0000\u00b9\u00ba\u0005\u0021\u0000\u0000\u00ba\u001d\u0001\u0000\u0000\u0000\u00bb\u00bc\u0005\u007c\u0000\u0000\u00bc\u00bd\u0005\u007c\u0000\u0000\u00bd\u001f\u0001\u0000\u0000\u0000\u00be\u00bf\u0005\u0026\u0000\u0000\u00bf\u00c0\u0005\u0026\u0000\u0000\u00c0\u0021\u0001\u0000\u0000\u0000\u00c1\u00c2\u0005\u003d\u0000\u0000\u00c2\u00c3\u0005\u003d\u0000\u0000\u00c3\u0023\u0001\u0000\u0000\u0000\u00c4\u00c5\u0005\u0021\u0000\u0000\u00c5\u00c6\u0005\u003d\u0000\u0000\u00c6\u0025\u0001\u0000\u0000\u0000\u00c7\u00c8\u0005\u003c\u0000\u0000\u00c8\u0027\u0001\u0000\u0000\u0000\u00c9\u00ca\u0005\u003e\u0000\u0000\u00ca\u0029\u0001\u0000\u0000\u0000\u00cb\u00cc\u0005\u003c\u0000\u0000\u00cc\u00cd\u0005\u003d\u0000\u0000\u00cd\u002b\u0001\u0000\u0000\u0000\u00ce\u00cf\u0005\u003e\u0000\u0000\u00cf\u00d0\u0005\u003d\u0000\u0000\u00d0\u002d\u0001\u0000\u0000\u0000\u00d1\u00d2\u0003\u0082\u0040\u0000\u00d2\u002f\u0001\u0000\u0000\u0000\u00d3\u00d4\u0005\u006e\u0000\u0000\u00d4\u00d5\u0005\u0075\u0000\u0000\u00d5\u00d6\u0005\u006c\u0000\u0000\u00d6\u00d7\u0005\u006c\u0000\u0000\u00d7\u0031\u0001\u0000\u0000\u0000\u00d8\u00d9\u0005\u0074\u0000\u0000\u00d9\u00da\u0005\u0072\u0000\u0000\u00da\u00db\u0005\u0075\u0000\u0000\u00db\u00dc\u0005\u0065\u0000\u0000\u00dc\u0033\u0001\u0000\u0000\u0000\u00dd\u00de\u0005\u0066\u0000\u0000\u00de\u00df\u0005\u0061\u0000\u0000\u00df\u00e0\u0005\u006c\u0000\u0000\u00e0\u00e1\u0005\u0073\u0000\u0000\u00e1\u00e2\u0005\u0065\u0000\u0000\u00e2\u0035\u0001\u0000\u0000\u0000\u00e3\u00e4\u0003\u0044\u0021\u0000\u00e4\u0037\u0001\u0000\u0000\u0000\u00e5\u00e8\u0003\u0044\u0021\u0000\u00e6\u00e8\u0003\u008a\u0044\u0000\u00e7\u00e5\u0001\u0000\u0000\u0000\u00e7\u00e6\u0001\u0000\u0000\u0000\u00e8\u00ea\u0001\u0000\u0000\u0000\u00e9\u00eb\u0003\u008e\u0046\u0000\u00ea\u00e9\u0001\u0000\u0000\u0000\u00ea\u00eb\u0001\u0000\u0000\u0000\u00eb\u00ed\u0001\u0000\u0000\u0000\u00ec\u00ee\u0003\u0092\u0048\u0000\u00ed\u00ec\u0001\u0000\u0000\u0000\u00ed\u00ee\u0001\u0000\u0000\u0000\u00ee\u0039\u0001\u0000\u0000\u0000\u00ef\u00f0\u0003\u0088\u0043\u0000\u00f0\u003b\u0001\u0000\u0000\u0000\u00f1\u00f2\u0007\u0000\u0000\u0000\u00f2\u003d\u0001\u0000\u0000\u0000\u00f3\u00f4\u0005\u0030\u0000\u0000\u00f4\u003f\u0001\u0000\u0000\u0000\u00f5\u00f6\u0002\u0031\u0039\u0000\u00f6\u0041\u0001\u0000\u0000\u0000\u00f7\u00fa\u0003\u003e\u001e\u0000\u00f8\u00fa\u0003\u0040\u001f\u0000\u00f9\u00f7\u0001\u0000\u0000\u0000\u00f9\u00f8\u0001\u0000\u0000\u0000\u00fa\u0043\u0001\u0000\u0000\u0000\u00fb\u0107\u0003\u003e\u001e\u0000\u00fc\u00fe\u0003\u006c\u0035\u0000\u00fd\u00fc\u0001\u0000\u0000\u0000\u00fd\u00fe\u0001\u0000\u0000\u0000\u00fe\u00ff\u0001\u0000\u0000\u0000\u00ff\u0103\u0003\u0040\u001f\u0000\u0100\u0102\u0003\u0042\u0020\u0000\u0101\u0100\u0001\u0000\u0000\u0000\u0102\u0105\u0001\u0000\u0000\u0000\u0103\u0101\u0001\u0000\u0000\u0000\u0103\u0104\u0001\u0000\u0000\u0000\u0104\u0107\u0001\u0000\u0000\u0000\u0105\u0103\u0001\u0000\u0000\u0000\u0106\u00fb\u0001\u0000\u0000\u0000\u0106\u00fd\u0001\u0000\u0000\u0000\u0107\u0045\u0001\u0000\u0000\u0000\u0108\u0109\u0007\u0001\u0000\u0000\u0109\u0047\u0001\u0000\u0000\u0000\u010a\u010b\u0007\u0002\u0000\u0000\u010b\u0049\u0001\u0000\u0000\u0000\u010c\u010d\u0007\u0003\u0000\u0000\u010d\u004b\u0001\u0000\u0000\u0000\u010e\u010f\u0007\u0004\u0000\u0000\u010f\u004d\u0001\u0000\u0000\u0000\u0110\u0111\u0007\u0005\u0000\u0000\u0111\u004f\u0001\u0000\u0000\u0000\u0112\u0113\u0007\u0006\u0000\u0000\u0113\u0051\u0001\u0000\u0000\u0000\u0114\u011c\u0003\u0042\u0020\u0000\u0115\u011c\u0003\u0046\u0022\u0000\u0116\u011c\u0003\u0048\u0023\u0000\u0117\u011c\u0003\u004a\u0024\u0000\u0118\u011c\u0003\u004c\u0025\u0000\u0119\u011c\u0003\u004e\u0026\u0000\u011a\u011c\u0003\u0050\u0027\u0000\u011b\u0114\u0001\u0000\u0000\u0000\u011b\u0115\u0001\u0000\u0000\u0000\u011b\u0116\u0001\u0000\u0000\u0000\u011b\u0117\u0001\u0000\u0000\u0000\u011b\u0118\u0001\u0000\u0000\u0000\u011b\u0119\u0001\u0000\u0000\u0000\u011b\u011a\u0001\u0000\u0000\u0000\u011c\u0053\u0001\u0000\u0000\u0000\u011d\u0121\u0003\u004c\u0025\u0000\u011e\u0122\u0002\u0038\u0039\u0000\u011f\u0122\u0003\u0046\u0022\u0000\u0120\u0122\u0003\u0048\u0023\u0000\u0121\u011e\u0001\u0000\u0000\u0000\u0121\u011f\u0001\u0000\u0000\u0000\u0121\u0120\u0001\u0000\u0000\u0000\u0122\u0123\u0001\u0000\u0000\u0000\u0123\u0124\u0003\u0052\u0028\u0000\u0124\u0125\u0003\u0052\u0028\u0000\u0125\u0055\u0001\u0000\u0000\u0000\u0126\u012b\u0003\u004c\u0025\u0000\u0127\u012c\u0003\u004a\u0024\u0000\u0128\u012c\u0003\u004c\u0025\u0000\u0129\u012c\u0003\u004e\u0026\u0000\u012a\u012c\u0003\u0050\u0027\u0000\u012b\u0127\u0001\u0000\u0000\u0000\u012b\u0128\u0001\u0000\u0000\u0000\u012b\u0129\u0001\u0000\u0000\u0000\u012b\u012a\u0001\u0000\u0000\u0000\u012c\u012d\u0001\u0000\u0000\u0000\u012d\u012e\u0003\u0052\u0028\u0000\u012e\u012f\u0003\u0052\u0028\u0000\u012f\u0057\u0001\u0000\u0000\u0000\u0130\u0137\u0003\u0042\u0020\u0000\u0131\u0137\u0003\u0046\u0022\u0000\u0132\u0137\u0003\u0048\u0023\u0000\u0133\u0137\u0003\u004a\u0024\u0000\u0134\u0137\u0003\u004e\u0026\u0000\u0135\u0137\u0003\u0050\u0027\u0000\u0136\u0130\u0001\u0000\u0000\u0000\u0136\u0131\u0001\u0000\u0000\u0000\u0136\u0132\u0001\u0000\u0000\u0000\u0136\u0133\u0001\u0000\u0000\u0000\u0136\u0134\u0001\u0000\u0000\u0000\u0136\u0135\u0001\u0000\u0000\u0000\u0137\u0138\u0001\u0000\u0000\u0000\u0138\u0139\u0003\u0052\u0028\u0000\u0139\u013a\u0003\u0052\u0028\u0000\u013a\u013b\u0003\u0052\u0028\u0000\u013b\u0142\u0001\u0000\u0000\u0000\u013c\u013d\u0003\u004c\u0025\u0000\u013d\u013e\u0002\u0030\u0037\u0000\u013e\u013f\u0003\u0052\u0028\u0000\u013f\u0140\u0003\u0052\u0028\u0000\u0140\u0142\u0001\u0000\u0000\u0000\u0141\u0136\u0001\u0000\u0000\u0000\u0141\u013c\u0001\u0000\u0000\u0000\u0142\u0059\u0001\u0000\u0000\u0000\u0143\u014a\u0003\u0058\u002b\u0000\u0144\u0145\u0003\u0054\u0029\u0000\u0145\u0146\u0003\u0068\u0033\u0000\u0146\u0147\u0005\u0075\u0000\u0000\u0147\u0148\u0003\u0056\u002a\u0000\u0148\u014a\u0001\u0000\u0000\u0000\u0149\u0143\u0001\u0000\u0000\u0000\u0149\u0144\u0001\u0000\u0000\u0000\u014a\u005b\u0001\u0000\u0000\u0000\u014b\u014c\u0007\u0007\u0000\u0000\u014c\u005d\u0001\u0000\u0000\u0000\u014d\u014e\u0007\u0008\u0000\u0000\u014e\u005f\u0001\u0000\u0000\u0000\u014f\u0152\u0003\u005c\u002d\u0000\u0150\u0152\u0003\u005e\u002e\u0000\u0151\u014f\u0001\u0000\u0000\u0000\u0151\u0150\u0001\u0000\u0000\u0000\u0152\u0061\u0001\u0000\u0000\u0000\u0153\u0154\u0005\u002a\u0000\u0000\u0154\u0063\u0001\u0000\u0000\u0000\u0155\u0156\u0005\u005b\u0000\u0000\u0156\u0065\u0001\u0000\u0000\u0000\u0157\u0158\u0005\u005f\u0000\u0000\u0158\u0067\u0001\u0000\u0000\u0000\u0159\u015a\u0005\u005c\u0000\u0000\u015a\u0069\u0001\u0000\u0000\u0000\u015b\u015c\u0005\u002b\u0000\u0000\u015c\u006b\u0001\u0000\u0000\u0000\u015d\u015e\u0005\u002d\u0000\u0000\u015e\u006d\u0001\u0000\u0000\u0000\u015f\u0163\u0003\u0060\u002f\u0000\u0160\u0163\u0003\u0066\u0032\u0000\u0161\u0163\u0007\u0009\u0000\u0000\u0162\u015f\u0001\u0000\u0000\u0000\u0162\u0160\u0001\u0000\u0000\u0000\u0162\u0161\u0001\u0000\u0000\u0000\u0163\u006f\u0001\u0000\u0000\u0000\u0164\u0167\u0003\u006e\u0036\u0000\u0165\u0167\u0003\u0042\u0020\u0000\u0166\u0164\u0001\u0000\u0000\u0000\u0166\u0165\u0001\u0000\u0000\u0000\u0167\u0071\u0001\u0000\u0000\u0000\u0168\u016c\u0003\u006e\u0036\u0000\u0169\u016b\u0003\u0070\u0037\u0000\u016a\u0169\u0001\u0000\u0000\u0000\u016b\u016e\u0001\u0000\u0000\u0000\u016c\u016a\u0001\u0000\u0000\u0000\u016c\u016d\u0001\u0000\u0000\u0000\u016d\u0073\u0001\u0000\u0000\u0000\u016e\u016c\u0001\u0000\u0000\u0000\u016f\u0174\u0007\u000a\u0000\u0000\u0170\u0174\u0003\u0068\u0033\u0000\u0171\u0172\u0005\u0075\u0000\u0000\u0172\u0174\u0003\u005a\u002c\u0000\u0173\u016f\u0001\u0000\u0000\u0000\u0173\u0170\u0001\u0000\u0000\u0000\u0173\u0171\u0001\u0000\u0000\u0000\u0174\u0075\u0001\u0000\u0000\u0000\u0175\u0176\u0007\u000b\u0000\u0000\u0176\u0077\u0001\u0000\u0000\u0000\u0177\u0178\u0003\u0068\u0033\u0000\u0178\u0079\u0001\u0000\u0000\u0000\u0179\u017a\u0005\u0027\u0000\u0000\u017a\u007b\u0001\u0000\u0000\u0000\u017b\u017c\u0005\u0022\u0000\u0000\u017c\u007d\u0001\u0000\u0000\u0000\u017d\u0186\u0003\u0076\u003a\u0000\u017e\u0186\u0003\u007a\u003c\u0000\u017f\u0180\u0003\u0078\u003b\u0000\u0180\u0181\u0003\u007c\u003d\u0000\u0181\u0186\u0001\u0000\u0000\u0000\u0182\u0183\u0003\u0078\u003b\u0000\u0183\u0184\u0003\u0074\u0039\u0000\u0184\u0186\u0001\u0000\u0000\u0000\u0185\u017d\u0001\u0000\u0000\u0000\u0185\u017e\u0001\u0000\u0000\u0000\u0185\u017f\u0001\u0000\u0000\u0000\u0185\u0182\u0001\u0000\u0000\u0000\u0186\u007f\u0001\u0000\u0000\u0000\u0187\u0190\u0003\u0076\u003a\u0000\u0188\u0190\u0003\u007c\u003d\u0000\u0189\u018a\u0003\u0078\u003b\u0000\u018a\u018b\u0003\u007a\u003c\u0000\u018b\u0190\u0001\u0000\u0000\u0000\u018c\u018d\u0003\u0078\u003b\u0000\u018d\u018e\u0003\u0074\u0039\u0000\u018e\u0190\u0001\u0000\u0000\u0000\u018f\u0187\u0001\u0000\u0000\u0000\u018f\u0188\u0001\u0000\u0000\u0000\u018f\u0189\u0001\u0000\u0000\u0000\u018f\u018c\u0001\u0000\u0000\u0000\u0190\u0081\u0001\u0000\u0000\u0000\u0191\u0195\u0003\u007c\u003d\u0000\u0192\u0194\u0003\u007e\u003e\u0000\u0193\u0192\u0001\u0000\u0000\u0000\u0194\u0197\u0001\u0000\u0000\u0000\u0195\u0193\u0001\u0000\u0000\u0000\u0195\u0196\u0001\u0000\u0000\u0000\u0196\u0198\u0001\u0000\u0000\u0000\u0197\u0195\u0001\u0000\u0000\u0000\u0198\u0199\u0003\u007c\u003d\u0000\u0199\u01a4\u0001\u0000\u0000\u0000\u019a\u019e\u0003\u007a\u003c\u0000\u019b\u019d\u0003\u0080\u003f\u0000\u019c\u019b\u0001\u0000\u0000\u0000\u019d\u01a0\u0001\u0000\u0000\u0000\u019e\u019c\u0001\u0000\u0000\u0000\u019e\u019f\u0001\u0000\u0000\u0000\u019f\u01a1\u0001\u0000\u0000\u0000\u01a0\u019e\u0001\u0000\u0000\u0000\u01a1\u01a2\u0003\u007a\u003c\u0000\u01a2\u01a4\u0001\u0000\u0000\u0000\u01a3\u0191\u0001\u0000\u0000\u0000\u01a3\u019a\u0001\u0000\u0000\u0000\u01a4\u0083\u0001\u0000\u0000\u0000\u01a5\u01a6\u0003\u005c\u002d\u0000\u01a6\u0085\u0001\u0000\u0000\u0000\u01a7\u01ab\u0003\u0084\u0041\u0000\u01a8\u01ab\u0003\u0066\u0032\u0000\u01a9\u01ab\u0003\u0042\u0020\u0000\u01aa\u01a7\u0001\u0000\u0000\u0000\u01aa\u01a8\u0001\u0000\u0000\u0000\u01aa\u01a9\u0001\u0000\u0000\u0000\u01ab\u0087\u0001\u0000\u0000\u0000\u01ac\u01b0\u0003\u0084\u0041\u0000\u01ad\u01af\u0003\u0086\u0042\u0000\u01ae\u01ad\u0001\u0000\u0000\u0000\u01af\u01b2\u0001\u0000\u0000\u0000\u01b0\u01ae\u0001\u0000\u0000\u0000\u01b0\u01b1\u0001\u0000\u0000\u0000\u01b1\u0089\u0001\u0000\u0000\u0000\u01b2\u01b0\u0001\u0000\u0000\u0000\u01b3\u01b4\u0003\u006c\u0035\u0000\u01b4\u01b5\u0003\u003e\u001e\u0000\u01b5\u008b\u0001\u0000\u0000\u0000\u01b6\u01b8\u0003\u0042\u0020\u0000\u01b7\u01b6\u0001\u0000\u0000\u0000\u01b8\u01b9\u0001\u0000\u0000\u0000\u01b9\u01b7\u0001\u0000\u0000\u0000\u01b9\u01ba\u0001\u0000\u0000\u0000\u01ba\u008d\u0001\u0000\u0000\u0000\u01bb\u01bc\u0005\u002e\u0000\u0000\u01bc\u01bd\u0003\u008c\u0045\u0000\u01bd\u008f\u0001\u0000\u0000\u0000\u01be\u01c1\u0003\u006c\u0035\u0000\u01bf\u01c1\u0003\u006a\u0034\u0000\u01c0\u01be\u0001\u0000\u0000\u0000\u01c0\u01bf\u0001\u0000\u0000\u0000\u01c1\u0091\u0001\u0000\u0000\u0000\u01c2\u01c4\u0003\u004e\u0026\u0000\u01c3\u01c5\u0003\u0090\u0047\u0000\u01c4\u01c3\u0001\u0000\u0000\u0000\u01c4\u01c5\u0001\u0000\u0000\u0000\u01c5\u01c6\u0001\u0000\u0000\u0000\u01c6\u01c7\u0003\u008c\u0045\u0000\u01c7\u0093\u0001\u0000\u0000\u0000\u01c8\u01c9\u0003\u0072\u0038\u0000\u01c9\u01ca\u0001\u0000\u0000\u0000\u01ca\u01cb\u0006\u0049\u0001\u0000\u01cb\u0095\u0001\u0000\u0000\u0000\u01cc\u01cd\u0003\u0062\u0030\u0000\u01cd\u01ce\u0001\u0000\u0000\u0000\u01ce\u01cf\u0006\u004a\u0002\u0000\u01cf\u01d0\u0006\u004a\u0001\u0000\u01d0\u0097\u0001\u0000\u0000\u0000\u01d1\u01d2\u0003\u0064\u0031\u0000\u01d2\u01d3\u0001\u0000\u0000\u0000\u01d3\u01d4\u0006\u004b\u0003\u0000\u01d4\u01d5\u0006\u004b\u0001\u0000\u01d5\u0099\u0001\u0000\u0000\u0000\u001e\u0000\u0001\u00e7\u00ea\u00ed\u00f9\u00fd\u0103\u0106\u011b\u0121\u012b\u0136\u0141\u0149\u0151\u0162\u0166\u016c\u0173\u0185\u018f\u0195\u019e\u01a3\u01aa\u01b0\u01b9\u01c0\u01c4\u0004\u0005\u0001\u0000\u0004\u0000\u0000\u0007\u0006\u0000\u0007\u0009\u0000"

        private val ATN = ATNDeserializer().deserialize(SERIALIZED_ATN.toCharArray())

        private val DECISION_TO_DFA = Array(ATN.numberOfDecisions) {
            DFA(ATN.getDecisionState(it)!!, it)
        }

        private val SHARED_CONTEXT_CACHE = PredictionContextCache()

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
    }

    public object Tokens {
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

    public object Channels {
        public const val DEFAULT_TOKEN_CHANNEL: Int = 0
        public const val HIDDEN: Int = 1
    }

    public object Modes {
        public const val DEFAULT_MODE: Int = 0
        public const val OPTIONALSHORTHANDMODE: Int = 1
    }

    override var interpreter: LexerATNSimulator =
        @Suppress("LeakingThis")
        LexerATNSimulator(this, ATN, DECISION_TO_DFA, SHARED_CONTEXT_CACHE)

    override val grammarFileName: String =
        "JsonPathLexer.g4"

    override val atn: ATN =
        ATN

    override val vocabulary: Vocabulary =
        VOCABULARY

    override val serializedATN: String =
        SERIALIZED_ATN

    override val ruleNames: Array<String> = arrayOf(
        "ROOT_IDENTIFIER", "CURRENT_NODE_IDENTIFIER", "BLANK", "DESCENDANT_SELECTOR", 
        "SHORTHAND_SELECTOR", "WILDCARD_SELECTOR", "COLON", "COMMA", "SQUARE_BRACKET_OPEN", 
        "SQUARE_BRACKET_CLOSE", "QUESTIONMARK", "BRACKET_OPEN", "BRACKET_CLOSE", 
        "LOGICAL_NOT_OP", "LOGICAL_OR_OP", "LOGICAL_AND_OP", "COMPARISON_OP_EQUALS", 
        "COMPARISON_OP_NOT_EQUALS", "COMPARISON_OP_SMALLER_THAN", "COMPARISON_OP_GREATER_THAN", 
        "COMPARISON_OP_SMALLER_THAN_OR_EQUALS", "COMPARISON_OP_GREATER_THAN_OR_EQUALS", 
        "STRING_LITERAL", "NULL", "TRUE", "FALSE", "INT", "NUMBER", "FUNCTION_NAME", 
        "BLANK_FRAGMENT", "ZERO", "DIGIT1", "DIGIT", "INT_FRAGMENT", "A", 
        "B", "C", "D", "E", "F", "HEXDIGIT", "HIGH_SURROGATE", "LOW_SURROGATE", 
        "NON_SURROGATE", "HEXCHAR", "LCALPHA", "UCALPHA", "ALPHA", "WILDCARD_SELECTOR_FRAGMENT", 
        "SQUARE_BRACKET_OPEN_FRAGMENT", "UNDERLINE", "BACKSLASH", "PLUS", 
        "MINUS", "NAME_FIRST", "NAME_CHAR", "MEMBER_NAME_SHORTHAND_FRAGMENT", 
        "ESCAPABLE", "UNESCAPED", "ESC", "SQUOTE", "DQUOTE", "DOUBLE_QUOTED", 
        "SINGLE_QUOTED", "STRING_LITERAL_FRAGMENT", "FUNCTION_NAME_FIRST", 
        "FUNCTION_NAME_CHAR", "FUNCTION_NAME_FRAGMENT", "NEGATIVE_ZERO", 
        "INT_WITH_POSSIBLE_ZERO_PREFIX", "DECIMAL_FRACTION", "SIGN", "EXPONENT", 
        "MEMBER_NAME_SHORTHAND", "WILDCARD_SELECTOR_1", "SQUARE_BRACKET_OPEN_1"
    )

    override val channelNames: Array<String> = arrayOf(
        "DEFAULT_TOKEN_CHANNEL", "HIDDEN",
    )

    override val modeNames: Array<String> = arrayOf(
        "DEFAULT_MODE", "optionalShorthandMode"
    )


}

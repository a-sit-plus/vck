package at.asitplus.jsonpath

import at.asitplus.jsonpath.core.Rfc9535Utils
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

@Suppress("unused")
class Rfc9535UtilsUnitTest : FreeSpec({
    "Rfc9535Utils.unpackStringLiteral Unit Tests" - {
        "rfc8259 conformance" - {
            "special escape characters" - {
                "double quoted" - {
                    "unescapes backslash to backslash" {
                        Rfc9535Utils.unpackStringLiteral("\"\\\\\"") shouldBe "\\"
                    }
                    "unescapes slash to slash" {
                        Rfc9535Utils.unpackStringLiteral("\"\\/\"") shouldBe "/"
                    }
                    "unescapes quotation mark to quotation mark" {
                        Rfc9535Utils.unpackStringLiteral("\"\\\"\"") shouldBe "\""
                    }
                    "unescapes b to backspace" {
                        Rfc9535Utils.unpackStringLiteral("\"\\b\"") shouldBe Char(0x0008).toString()
                    }
                    "unescapes f to form feed" {
                        Rfc9535Utils.unpackStringLiteral("\"\\f\"") shouldBe Char(0x000C).toString()
                    }
                    "unescapes n to newline" {
                        Rfc9535Utils.unpackStringLiteral("\"\\n\"") shouldBe "\n"
                    }
                    "unescapes r to carriage return" {
                        Rfc9535Utils.unpackStringLiteral("\"\\r\"") shouldBe "\r"
                    }
                    "unescapes t to horizontal tab" {
                        Rfc9535Utils.unpackStringLiteral("\"\\t\"") shouldBe "\t"
                    }
                }
                "single quoted" - {
                    "unescapes backslash to backslash" {
                        Rfc9535Utils.unpackStringLiteral("'\\\\'") shouldBe "\\"
                    }
                    "unescapes slash to slash" {
                        Rfc9535Utils.unpackStringLiteral("'\\/'") shouldBe "/"
                    }
                    "unescapes quotation mark to quotation mark" {
                        Rfc9535Utils.unpackStringLiteral("'\\''") shouldBe "'"
                    }
                    "unescapes b to backspace" {
                        Rfc9535Utils.unpackStringLiteral("'\\b'") shouldBe Char(0x0008).toString()
                    }
                    "unescapes f to form feed" {
                        Rfc9535Utils.unpackStringLiteral("'\\f'") shouldBe Char(0x000C).toString()
                    }
                    "unescapes n to newline" {
                        Rfc9535Utils.unpackStringLiteral("'\\n'") shouldBe "\n"
                    }
                    "unescapes r to carriage return" {
                        Rfc9535Utils.unpackStringLiteral("'\\r'") shouldBe "\r"
                    }
                    "unescapes t to horizontal tab" {
                        Rfc9535Utils.unpackStringLiteral("'\\t'") shouldBe "\t"
                    }
                }
            }
        }
    }
    "Rfc9535Utils.switchToSingleQuotedString Unit Tests" - {
        "rfc8259 conformance" - {
            "special escape characters" - {
                "\"\\\\\"" {
                    Rfc9535Utils.switchToSingleQuotedString(this.testScope.testCase.name.originalName)
                        .let {
                            val expectedResult = "'\\\\'"
                            it shouldBe expectedResult
                            Rfc9535Utils.switchToSingleQuotedString(it) shouldBe expectedResult
                        }
                }
                "\"\\/\"" {
                    Rfc9535Utils.switchToSingleQuotedString(this.testScope.testCase.name.originalName)
                        .let {
                            val expectedResult = "'\\/'"
                            it shouldBe expectedResult
                            Rfc9535Utils.switchToSingleQuotedString(it) shouldBe expectedResult
                        }
                }
                "\"\\\"\"" {
                    Rfc9535Utils.switchToSingleQuotedString(this.testScope.testCase.name.originalName)
                        .let {
                            val expectedResult = "'\"'"
                            it shouldBe expectedResult
                            Rfc9535Utils.switchToSingleQuotedString(it) shouldBe expectedResult
                        }
                }
                "\"'\"" {
                    Rfc9535Utils.switchToSingleQuotedString(this.testScope.testCase.name.originalName)
                        .let {
                            val expectedResult = "'\\''"
                            it shouldBe expectedResult
                            Rfc9535Utils.switchToSingleQuotedString(it) shouldBe expectedResult
                        }
                }
                "\"\\b\"" {
                    Rfc9535Utils.switchToSingleQuotedString(this.testScope.testCase.name.originalName)
                        .let {
                            val expectedResult = "'\\b'"
                            it shouldBe expectedResult
                            Rfc9535Utils.switchToSingleQuotedString(it) shouldBe expectedResult
                        }
                }
                "\"\\f\"" {
                    Rfc9535Utils.switchToSingleQuotedString(this.testScope.testCase.name.originalName)
                        .let {
                            val expectedResult = "'\\f'"
                            it shouldBe expectedResult
                            Rfc9535Utils.switchToSingleQuotedString(it) shouldBe expectedResult
                        }
                }
                "\"\\n\"" {
                    Rfc9535Utils.switchToSingleQuotedString(this.testScope.testCase.name.originalName)
                        .let {
                            val expectedResult = "'\\n'"
                            it shouldBe expectedResult
                            Rfc9535Utils.switchToSingleQuotedString(it) shouldBe expectedResult
                        }
                }
                "\"\\r\"" {
                    Rfc9535Utils.switchToSingleQuotedString(this.testScope.testCase.name.originalName)
                        .let {
                            val expectedResult = "'\\r'"
                            it shouldBe expectedResult
                            Rfc9535Utils.switchToSingleQuotedString(it) shouldBe expectedResult
                        }
                }
                "\"\\t\"" {
                    Rfc9535Utils.switchToSingleQuotedString(this.testScope.testCase.name.originalName)
                        .let {
                            val expectedResult = "'\\t'"
                            it shouldBe expectedResult
                            Rfc9535Utils.switchToSingleQuotedString(it) shouldBe expectedResult
                        }
                }
            }
        }
    }
    "Rfc9535Utils.switchToDoubleQuotedString Unit Tests" - {
        "rfc8259 conformance" - {
            "special escape characters" - {
                "'\\\\'" {
                    Rfc9535Utils.switchToDoubleQuotedString(this.testScope.testCase.name.originalName)
                        .let {
                            val expectedResult = "\"\\\\\""
                            it shouldBe expectedResult
                            Rfc9535Utils.switchToDoubleQuotedString(it) shouldBe expectedResult
                        }
                }
                "'\\/'" {
                    Rfc9535Utils.switchToDoubleQuotedString(this.testScope.testCase.name.originalName)
                        .let {
                            val expectedResult = "\"\\/\""
                            it shouldBe expectedResult
                            Rfc9535Utils.switchToDoubleQuotedString(it) shouldBe expectedResult
                        }
                }
                "'\"'" {
                    Rfc9535Utils.switchToDoubleQuotedString(this.testScope.testCase.name.originalName)
                        .let {
                            val expectedResult = "\"\\\"\""
                            it shouldBe expectedResult
                            Rfc9535Utils.switchToDoubleQuotedString(it) shouldBe expectedResult
                        }
                }
                "'\\''" {
                    Rfc9535Utils.switchToDoubleQuotedString(this.testScope.testCase.name.originalName)
                        .let {
                            val expectedResult = "\"'\""
                            it shouldBe expectedResult
                            Rfc9535Utils.switchToDoubleQuotedString(it) shouldBe expectedResult
                        }
                }
                "'\\b'" {
                    Rfc9535Utils.switchToDoubleQuotedString(this.testScope.testCase.name.originalName)
                        .let {
                            val expectedResult = "\"\\b\""
                            it shouldBe expectedResult
                            Rfc9535Utils.switchToDoubleQuotedString(it) shouldBe expectedResult
                        }
                }
                "'\\f'" {
                    Rfc9535Utils.switchToDoubleQuotedString(this.testScope.testCase.name.originalName)
                        .let {
                            val expectedResult = "\"\\f\""
                            it shouldBe expectedResult
                            Rfc9535Utils.switchToDoubleQuotedString(it) shouldBe expectedResult
                        }
                }
                "'\\n'" {
                    Rfc9535Utils.switchToDoubleQuotedString(this.testScope.testCase.name.originalName)
                        .let {
                            val expectedResult = "\"\\n\""
                            it shouldBe expectedResult
                            Rfc9535Utils.switchToDoubleQuotedString(it) shouldBe expectedResult
                        }
                }
                "'\\r'" {
                    Rfc9535Utils.switchToDoubleQuotedString(this.testScope.testCase.name.originalName)
                        .let {
                            val expectedResult = "\"\\r\""
                            it shouldBe expectedResult
                            Rfc9535Utils.switchToDoubleQuotedString(it) shouldBe expectedResult
                        }
                }
                "'\\t'" {
                    Rfc9535Utils.switchToDoubleQuotedString(this.testScope.testCase.name.originalName)
                        .let {
                            val expectedResult = "\"\\t\""
                            it shouldBe expectedResult
                            Rfc9535Utils.switchToDoubleQuotedString(it) shouldBe expectedResult
                        }
                }
            }
        }
    }
})
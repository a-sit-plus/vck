// specification: https://datatracker.ietf.org/doc/html/rfc8259#section-7

lexer grammar JsonStringLiteralLexer;

DQUOTE: DQUOTE_FRAGMENT;

UNESCAPED:   '\u0020' | '\u0021' |                      // see RFC 8259
                 // omit 0x22 "
              '\u0023'..'\u005B' |
                 // omit 0x5C \
              '\u005D'..'\uD7FF' |
                 // skip surrogate code points
                 //  - a string containing only the G clef character (U+1D11E) may be represented as "\uD834\uDD1E".
              '\uE000'..'\u{10FFFF}'
              ;


ESC: BACKSLASH -> mode(EscapedMode);

mode EscapedMode;

// special escapables
ESCAPED_DQUOTE: DQUOTE_FRAGMENT -> mode(DEFAULT_MODE);
ESCAPED_BACKSLASH: BACKSLASH -> mode(DEFAULT_MODE);
ESCAPED_SLASH: '/' -> mode(DEFAULT_MODE);
ESCAPED_LOWERCASE_B: 'b' -> mode(DEFAULT_MODE);
ESCAPED_LOWERCASE_F: 'f' -> mode(DEFAULT_MODE);
ESCAPED_LOWERCASE_N: 'n' -> mode(DEFAULT_MODE);
ESCAPED_LOWERCASE_R: 'r' -> mode(DEFAULT_MODE);
ESCAPED_LOWERCASE_T: 't' -> mode(DEFAULT_MODE);

// unicode escapable
UNICODE_ESCAPE: 'u' -> mode(UnicodeEscapedMode);

mode UnicodeEscapedMode;

NON_SURROGATE: NON_SURROGATE_FRAGMENT -> mode(DEFAULT_MODE);
HIGH_SURROGATE: HIGH_SURROGATE_FRAGMENT -> mode(DEFAULT_MODE);
LOW_SURROGATE: LOW_SURROGATE_FRAGMENT -> mode(DEFAULT_MODE);



fragment DQUOTE_FRAGMENT: '"';
fragment SQUOTE_FRAGMENT: '\'';
fragment BACKSLASH: '\\';

fragment ZERO: '\u0030';
fragment DIGIT1: '\u0031'..'\u0039';
fragment DIGIT: ZERO | DIGIT1;
fragment A : 'A' | 'a';
fragment B : 'B' | 'b';
fragment C : 'C' | 'c';
fragment D : 'D' | 'd';
fragment E : 'E' | 'e';
fragment F : 'F' | 'f';
fragment HEXDIGIT : DIGIT | A | B | C | D | E | F;

fragment HIGH_SURROGATE_FRAGMENT      : D ('8'|'9'|A|B) (HEXDIGIT HEXDIGIT);
fragment LOW_SURROGATE_FRAGMENT       : D (C|D|E|F) (HEXDIGIT HEXDIGIT);
fragment NON_SURROGATE_FRAGMENT       : ((DIGIT | A|B|C|E|F) (HEXDIGIT HEXDIGIT HEXDIGIT)) |
                                (D '\u0030'..'\u0037' (HEXDIGIT HEXDIGIT) );
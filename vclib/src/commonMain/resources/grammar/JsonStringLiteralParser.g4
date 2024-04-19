// specification: https://datatracker.ietf.org/doc/rfc9535/

parser grammar JsonStringLiteralParser;

options { tokenVocab=JsonStringLiteralLexer; }

string: (DQUOTE char* DQUOTE);    // "string"

char       : UNESCAPED |
              (ESC escapable);

escapable:  specialEscapable | UNICODE_ESCAPE hexchar; //  uXXXX U+XXXX

hexchar: NON_SURROGATE | (HIGH_SURROGATE ESC UNICODE_ESCAPE LOW_SURROGATE);


specialEscapable
    : escapedDQuote
    | escapedBackslash
    | escapedSlash
    | escapedLowercaseB
    | escapedLowercaseF
    | escapedLowercaseN
    | escapedLowercaseR
    | escapedLowercaseT
    ;

escapedDQuote: ESCAPED_DQUOTE;
escapedBackslash: ESCAPED_BACKSLASH;
escapedSlash: ESCAPED_SLASH;
escapedLowercaseB: ESCAPED_LOWERCASE_B;
escapedLowercaseF: ESCAPED_LOWERCASE_F;
escapedLowercaseN: ESCAPED_LOWERCASE_N;
escapedLowercaseR: ESCAPED_LOWERCASE_R;
escapedLowercaseT: ESCAPED_LOWERCASE_T;
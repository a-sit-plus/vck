// 1. converted from abnf using tool:
//      - http://www.robertpinchbeck.com/abnf_to_antlr/Default.aspx
// 2. manually resolved lexer ambiguities
lexer grammar JsonPathLexer;

// normal
ROOT_IDENTIFIER: '$';
CURRENT_NODE_IDENTIFIER : '@';

BLANK: BLANK_FRAGMENT;

DESCENDANT_SELECTOR: '..' -> pushMode(optionalShorthandMode);
SHORTHAND_SELECTOR: '.' -> pushMode(optionalShorthandMode);
WILDCARD_SELECTOR: WILDCARD_SELECTOR_FRAGMENT;

COLON: ':';
COMMA: ',';
SQUARE_BRACKET_OPEN: SQUARE_BRACKET_OPEN_FRAGMENT;
SQUARE_BRACKET_CLOSE: ']';

QUESTIONMARK: '?';
BRACKET_OPEN: '(';
BRACKET_CLOSE: ')';

LOGICAL_NOT_OP: '!';                // logical NOT operator
LOGICAL_OR_OP: '||';
LOGICAL_AND_OP: '&&';

COMPARISON_OP_EQUALS        : '==';
COMPARISON_OP_NOT_EQUALS    : '!=';
COMPARISON_OP_SMALLER_THAN      : '<';
COMPARISON_OP_GREATER_THAN      : '>';
COMPARISON_OP_SMALLER_THAN_OR_EQUALS    : '<=';
COMPARISON_OP_GREATER_THAN_OR_EQUALS    : '>=';

STRING_LITERAL: STRING_LITERAL_FRAGMENT;

NULL                : 'null';
TRUE                : 'true';
FALSE               : 'false';
INT: INT_FRAGMENT;      // match before number, and just accept both for the number literal
NUMBER: (INT_FRAGMENT | NEGATIVE_ZERO) DECIMAL_FRACTION? EXPONENT?;

FUNCTION_NAME: FUNCTION_NAME_FRAGMENT;








fragment BLANK_FRAGMENT: '\u0020' |    // Space
                '\u0009' |    // Horizontal tab
                '\u000A' |    // Line feed or New line
                '\u000D';      // Carriage return

fragment ZERO: '\u0030';
fragment DIGIT1: '\u0031'..'\u0039';
fragment DIGIT: ZERO | DIGIT1;
fragment INT_FRAGMENT: ZERO | (MINUS? DIGIT1 DIGIT*);
fragment A : 'A' | 'a';
fragment B : 'B' | 'b';
fragment C : 'C' | 'c';
fragment D : 'D' | 'd';
fragment E : 'E' | 'e';
fragment F : 'F' | 'f';
fragment HEXDIGIT : DIGIT | A | B | C | D | E | F;

fragment HIGH_SURROGATE      : D ('8'|'9'|A|B) (HEXDIGIT HEXDIGIT);
fragment LOW_SURROGATE       : D (C|D|E|F) (HEXDIGIT HEXDIGIT);
fragment NON_SURROGATE       : ((DIGIT | A|B|C|E|F) (HEXDIGIT HEXDIGIT HEXDIGIT)) |
                                (D '\u0030'..'\u0037' (HEXDIGIT HEXDIGIT) );
fragment HEXCHAR              : NON_SURROGATE |
                                (HIGH_SURROGATE BACKSLASH 'u' LOW_SURROGATE);

fragment LCALPHA             : [a-z];
fragment UCALPHA             : [A-Z];
fragment ALPHA               : LCALPHA | UCALPHA;

fragment WILDCARD_SELECTOR_FRAGMENT: '*';
fragment SQUARE_BRACKET_OPEN_FRAGMENT: '[';
fragment UNDERLINE: '_';
fragment BACKSLASH: '\\';
fragment PLUS: '+';
fragment MINUS: '-';

fragment NAME_FIRST:  ALPHA |
                      UNDERLINE   |
                      '\u0080'..'\uD7FF' |
                         // skip surrogate code points
                      '\uE000'..'\u{10FFFF}';
fragment NAME_CHAR            : NAME_FIRST | DIGIT;
fragment MEMBER_NAME_SHORTHAND_FRAGMENT: NAME_FIRST NAME_CHAR*;

fragment ESCAPABLE:  'b' | // b BS backspace U+0008
                      'f' | // f FF form feed U+000C
                      'n' | // n LF line feed U+000A
                      'r' | // r CR carriage return U+000D
                      't' | // t HT horizontal tab U+0009
                      '/'  | // / slash (solidus) U+002F
                      BACKSLASH  | // \ backslash (reverse solidus) U+005C
                      ('u' HEXCHAR); //  uXXXX U+XXXX

fragment UNESCAPED:   '\u0020' | '\u0021' |                      // see RFC 8259
                         // omit 0x22 "
                      '\u0023'..'\u0026' |
                         // omit 0x27 '
                      '\u0028'..'\u005B' |
                         // omit 0x5C \
                      '\u005D'..'\uD7FF' |
                         // skip surrogate code points
                      '\uE000'..'\u{10FFFF}'
                      ;

fragment ESC: BACKSLASH;
fragment SQUOTE: '\'';
fragment DQUOTE: '"';
fragment DOUBLE_QUOTED       : UNESCAPED |
                             SQUOTE |                    // '
                              (ESC DQUOTE)  |                    // \"
                              (ESC ESCAPABLE);

fragment SINGLE_QUOTED       : UNESCAPED |
                             DQUOTE |                    // "
                              (ESC SQUOTE)  |                    // \'
                              (ESC ESCAPABLE);

// needs to be a single token in order to disabiguate escapable and unescaped characters
// from ones in MEMBER_NAME_SHORTHAND or FUNCTION_NAME
fragment STRING_LITERAL_FRAGMENT
    : (DQUOTE DOUBLE_QUOTED* DQUOTE)    // "string"
    | (SQUOTE SINGLE_QUOTED* SQUOTE)    // 'string'
    ;

fragment FUNCTION_NAME_FIRST: LCALPHA;
fragment FUNCTION_NAME_CHAR: FUNCTION_NAME_FIRST | UNDERLINE | DIGIT;
fragment FUNCTION_NAME_FRAGMENT: FUNCTION_NAME_FIRST FUNCTION_NAME_CHAR*;

fragment NEGATIVE_ZERO: MINUS ZERO;
fragment INT_WITH_POSSIBLE_ZERO_PREFIX: DIGIT+;
fragment DECIMAL_FRACTION: '.' INT_WITH_POSSIBLE_ZERO_PREFIX;

fragment SIGN: (MINUS | PLUS);
fragment EXPONENT: E SIGN? INT_WITH_POSSIBLE_ZERO_PREFIX;    // decimal exponent




mode optionalShorthandMode; // needed to disabiguate MEMBER_NAME_SHORTHAND from FUNCTION_NAME
MEMBER_NAME_SHORTHAND: MEMBER_NAME_SHORTHAND_FRAGMENT -> popMode;
WILDCARD_SELECTOR_1: WILDCARD_SELECTOR_FRAGMENT -> type(WILDCARD_SELECTOR), popMode;
SQUARE_BRACKET_OPEN_1: SQUARE_BRACKET_OPEN_FRAGMENT -> type(SQUARE_BRACKET_OPEN), popMode;
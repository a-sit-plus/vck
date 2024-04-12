/*
Source: https://datatracker.ietf.org/doc/rfc9535/
- Appendix A

This has been manually translated from the abnf format.
Translation considerations:
- Alphabetic characters in quoted strings are case-insensitive in ABNF
    - many characters are therefore represented as their UTF-8 codepoint in the abnf grammar
*/

grammar JSONPath;

jsonpathQuery
    : rootIdentifier segments
    ;

segments
    : (S segment)*
    ;

B
    : ' '
    | ' '
    | '\n'
    | '\r'
    ;

fragment S
    : B*
    ; // optional blank space

rootIdentifier: ROOT_IDENTIFIER;
ROOT_IDENTIFIER
    : '$'
    ;

selector
    : nameSelector
    | wildcardSelector
    | sliceSelector
    | indexSelector
    | filterSelector
    ;

nameSelector
    : stringLiteral
    ;

stringLiteral
    : doubleQuotedLiteral
    | singleQuotedLiteral
    ;

doubleQuotedLiteral
    : DQUOTE doubleQuoted* DQUOTE // "string"
    ;

singleQuotedLiteral
    : SQUOTE singleQuoted* SQUOTE // 'string'
    ;

doubleQuoted
    : unescaped
    | SQUOTE
    | ESC DQUOTE
    | ESC escapable
    ;

SQUOTE
    : '\''
    ;

DQUOTE
    : '"'
    ;

singleQuoted
    : unescaped
    | DQUOTE
    | ESC SQUOTE
    | ESC escapable
    ;

ESC
    : BACKSLASH
    ;

SLASH
    : '/'
    ;

BACKSLASH
    : '\\'
    ;

unescaped: UNESCAPED;
UNESCAPED: [\u0020-\u0021\u0023-\u0026\u0028-\u005B\u005D-\uD7FF\uE000-\u{10FFFF}];

escapable: ESCAPABLE;
ESCAPABLE
    : 'b'
    | 'f'
    | 'n'
    | 'r'
    | 't'
    | SLASH
    | BACKSLASH
    | 'u' HEXCHAR   // unicode characters uXXXX, U+XXXX
    ;

HEXCHAR
    : NON_SURROGATE
    | (HIGH_SURROGATE BACKSLASH 'u' LOW_SURROGATE)
    ;

NON_SURROGATE
    : ((DIGIT | 'a' | 'A' | 'b' | 'B' | 'c' | 'C' | /* NO D */ 'e' | 'E' | 'f' | 'F') HEXDIG{3})
    | (('d' | 'D') [\u0030-\u0037] HEXDIG{2} )
    ;

HIGH_SURROGATE
    : ('d' | 'D') ('8'|'9'| 'a' | 'A' | 'b' | 'B') HEXDIG{2}
    ;

LOW_SURROGATE
    : ('d' | 'D') ('c' | 'C' |'d' | 'D' | 'e' | 'E' | 'f' | 'F') HEXDIG{2}
    ;

HEXDIG
    : DIGIT
    | 'a' | 'A'
    | 'b' | 'B'
    | 'c' | 'C'
    | 'd' | 'D'
    | 'e' | 'E'
    | 'f' | 'F'
    ;

wildcardSelector: WILDCARD_SELECTOR;
WILDCARD_SELECTOR
    : '*'
    ;

indexSelector
    : int
    ;

int
    : '0'
    | (minus? DIGIT1 DIGIT*)
    ;

plus: PLUS;
PLUS
    : '+'
    ;

minus: MINUS;
MINUS
    : '-'
    ;

DIGIT1
    : [\u0031-\u0039]
    ; // 1-9 nonZero digit



sliceSelector
    : (start S)? ':' S (end S)? (':' (S step )?)?
    ;

start
    : int
    ; // included in selection

end
    : int
    ; // not included in selection

step
    : int
    ; // default: 1



filterSelector
    : '?' S logicalExpr
    ;

logicalExpr
    : logicalOrExpr
    ;

logicalOrExpr
    : logicalAndExpr (S '||' S logicalAndExpr)*
    ; // disjunction; binds less tightly than conjunction

logicalAndExpr
    : basicExpr (S '&&' S basicExpr)*
    ; // conjunction; binds more tightly than disjunction

basicExpr
    : parenExpr
    | comparisonExpr
    | testExpr
    ;

parenExpr
    : (LOGICAL_NOT_OP S)? '(' S logicalExpr S ')'
    ; // parenthesized expression

LOGICAL_NOT_OP
    : '!'
    ; // logical NOT operator

testExpr
    : (LOGICAL_NOT_OP S)? (filterQuery | functionExpr)
    ;

filterQuery
    : relQuery | jsonpathQuery
    ;

relQuery
    : CURRENT_NODE_IDENTIFIER segments
    ;

CURRENT_NODE_IDENTIFIER
    : '@'
    ;

comparisonExpr
    : comparable S comparisonOp S comparable
    ;

literal
    : number
    | stringLiteral
    | true | false
    | null
    ;

comparable
    : literal
    | singularQuery // singular query value
    | functionExpr // ValueType
    ;

comparisonOp
    : equalsOp | notEqualsOp
    | smallerThanOp | greaterThanOp
    | smallerOrEqualsOp | greaterOrEqualsOp
    ;

equalsOp: EQUALS_OP;
EQUALS_OP
    : '=='
    ;

notEqualsOp: NOT_EQUALS_OP;
NOT_EQUALS_OP
    : '!='
    ;

smallerThanOp: SMALLER_THAN_OP;
SMALLER_THAN_OP
    : '<'
    ;

greaterThanOp: GREATER_THAN_OP;
GREATER_THAN_OP
    : '>'
    ;

smallerOrEqualsOp: SMALLER_OR_EQUALS_OP;
SMALLER_OR_EQUALS_OP
    : '<='
    ;

greaterOrEqualsOp: GREATER_OR_EQUALS_OP;
GREATER_OR_EQUALS_OP
    : '>='
    ;

singularQuery
    : relSingularQuery
    | absSingularQuery
    ;

relSingularQuery
    : CURRENT_NODE_IDENTIFIER singularQuerySegments
    ;

absSingularQuery
    : ROOT_IDENTIFIER singularQuerySegments
    ;

singularQuerySegments
    : (S (nameSegment | indexSegment))*
    ;

nameSegment
    : ('[' nameSelector ']')
    | ('.' memberNameShorthand)
    ;

indexSegment
    : '[' indexSelector ']'
    ;

number
    : (int | '-0') frac? exp?
    ; // decimal number

frac
    : '.' DIGIT+
    ; // decimal fraction

exp
    : ('e' | 'E') ( minus | plus )? DIGIT+
    ; // decimal exponent

true: TRUE;
TRUE
    : 'true'
    ;

false: FALSE;
FALSE
    : 'false'
    ;

null: NULL;
NULL
    : 'null'
    ;

functionName
    : functionNameFirst functionNameChar*
    ;

functionNameFirst
    : LCALPHA
    ;

functionNameChar
    : functionNameFirst
    | '_'
    | DIGIT
    ;

LCALPHA
    : [\u0065-\u0090]
    ; // 'a'..'z'

functionExpr
    : functionName '(' S (functionArgument (S ',' S functionArgument)*)? S ')'
    ;

functionArgument
    : literal
    | filterQuery // includes singular-query
    | logicalExpr
    | functionExpr
    ;

segment
    : childSegment
    | descendantSegment
    ;

childSegment
    : bracketedSelection
    | '.' (wildcardSelector | memberNameShorthand)
    ;

bracketedSelection
    : '[' S selector (S ',' S selector)* S ']'
    ;

memberNameShorthand
    : nameFirst nameChar*
    ;

nameFirst: NAME_FIRST;
NAME_FIRST
    : ALPHA
    | '_'
    | [\u0080-\uD7FF]
    | [\uE000-\u{10FFFF}]
    ;

nameChar
    : nameFirst
    | DIGIT
    ;

DIGIT
    : [\u0030-\u0039]
    ; // 0-9

ALPHA
    : [\u0041-\u005A]
    | [\u0061-\u007A]
    ; // A-Z | a-z

descendantSegment
    : '..' (
        bracketedSelection
        | wildcardSelector
        | memberNameShorthand
    )
    ;

normalizedPath
    : ROOT_IDENTIFIER normalIndexSegment*
    ;

normalIndexSegment
    : '[' normalSelector ']'
    ;

normalSelector
    : normalNameSelector
    | normalIndexSelector
    ;

normalNameSelector
    : DQUOTE normalSingleQuoted* DQUOTE
    ; // 'string'

normalSingleQuoted
    : normalUnescaped
    | ESC normalEscapable
    ;

normalUnescaped: NORMAL_UNESCAPED;
NORMAL_UNESCAPED
    : [\u0020-\u0026]
    | [\u0028-\u005B]
    | [\u005D-\uD7FF]
    | [\uE000-\u{10FFFF}]
    ;

normalEscapable: NORMAL_ESCAPABLE;
NORMAL_ESCAPABLE
    : 'b' // BS backspace U+0008
    | 'f' // FF form feed U+000C
    | 'n' // LF line feed U+000A
    | 'r' // CR carriage return U+000D
    | 't' // HT horizontal tab U+0009
    | SQUOTE
    | BACKSLASH
    | 'u' NORMAL_HEXCHAR // certain values u00xx U+00XX
    ;

NORMAL_HEXCHAR
    : '00'
    (
        ('0' [\u0030-\u0037]) // '00'-'07'
        | ('0b')
        | ('0' [\u0065-\u0066]) // '0e'-'0f'
        | ('1' NORMAL_HEXDIG)
    )
    ;

NORMAL_HEXDIG
    : DIGIT
    | [\u0061-\u0066]
    ; // '0'-'9', 'a'-'f'

normalIndexSelector
    : '0' | (DIGIT1 *DIGIT)
    ; // nonNegative decimal integer

/* converted from abnf using tool: http://www.robertpinchbeck.com/abnf_to_antlr/Default.aspx
Conversion Notes:
1. replaced the abnf values for true, false and null with strings, which are case-insensitive in abnf, and correct the resulting production rules for true, false and null
2. added grammar name
3. moved lexer rules below parser rules
4. replaced COMPARISON_OP with one parser rule for each operator
5. created parser rule for wildcard selector, true, false and null
*/

grammar JSONPath;


jsonpath_query      : rootSegment segments;
rootSegment: ROOT_IDENTIFIER;
segments            : (s segment)*;
s                   : B*;        // optional blank space
selector            : name_selector |
                      wildcardSelector |
                      slice_selector |
                      index_selector |
                      filter_selector;
wildcardSelector    : WILDCARD_SELECTOR;
name_selector       : string_literal;

string_literal      : ('\u0022' double_quoted* '\u0022') |     // "string"
                      ('\u0027' single_quoted* '\u0027');       // 'string'

double_quoted       : UNESCAPED |
                      SQUOTE      |                    // '
                      (ESC DQUOTE)  |                    // \"
                      (ESC escapable);

single_quoted       : UNESCAPED |
                      DQUOTE      |                    // "
                      (ESC SQUOTE)  |                    // \'
                      (ESC escapable);

escapable           : '\u0062' | // b BS backspace U+0008
                      '\u0066' | // f FF form feed U+000C
                      '\u006E' | // n LF line feed U+000A
                      '\u0072' | // r CR carriage return U+000D
                      '\u0074' | // t HT horizontal tab U+0009
                      '/'  | // / slash (solidus) U+002F
                      '\\'  | // \ backslash (reverse solidus) U+005C
                      ('\u0075' hexchar); //  uXXXX U+XXXX

hexchar             : non_surrogate |
                      (high_surrogate '\\' '\u0075' low_surrogate);
non_surrogate       : ((DIGIT | ('A' | 'a')|('B' | 'b')|('C' | 'c') | ('E' | 'e')|('F' | 'f')) (hexdig hexdig hexdig)) |
                      (('D' | 'd') NUMBERS_ZERO_UNTIL_SEVEN (hexdig hexdig) );
high_surrogate      : ('D' | 'd') ('8'|'9'|('A' | 'a')|('B' | 'b')) (hexdig hexdig);
low_surrogate       : ('D' | 'd') (('C' | 'c')|('D' | 'd')|('E' | 'e')|('F' | 'f')) (hexdig hexdig);

hexdig              : DIGIT | ('A' | 'a') | ('B' | 'b') | ('C' | 'c') | ('D' | 'd') | ('E' | 'e') | ('F' | 'f');
index_selector      : int_1;                        // decimal integer

int_1                 : '0' |
                      (('-')? DIGIT1 DIGIT*);      // - optional
slice_selector      : (start s)? ':' s (end s)? (':' (s step )?)?;

start               : int_1;       // included in selection
end                 : int_1;       // not included in selection
step                : int_1;       // default: 1
filter_selector     : '?' s logical_expr;
logical_expr        : logical_or_expr;
logical_or_expr     : logical_and_expr (s ('|' '|') s logical_and_expr)*;
                        // disjunction
                        // binds less tightly than conjunction
logical_and_expr    : basic_expr (s ('&' '&') s basic_expr)*;
                        // conjunction
                        // binds more tightly than disjunction

basic_expr          : paren_expr |
                      comparison_expr |
                      test_expr;

paren_expr          : (LOGICAL_NOT_OP s)? '(' s logical_expr s ')';
                                        // parenthesized expression
test_expr           : (LOGICAL_NOT_OP s)?
                      (filter_query | // existence/non-existence
                       function_expr); // LogicalType or NodesType
filter_query        : rel_query | jsonpath_query;
rel_query           : CURRENT_NODE_IDENTIFIER segments;
comparison_expr     : comparable s comparisonOp s comparable;
literal             : number | string_literal |
                      true | false | null;
null: NULL_1;
true: TRUE_1;
false: FALSE_1;
comparable          : literal |
                      singular_query | // singular query value
                      function_expr;    // ValueType

singular_query      : rel_singular_query | abs_singular_query;
rel_singular_query  : CURRENT_NODE_IDENTIFIER singular_query_segments;
abs_singular_query  : ROOT_IDENTIFIER singular_query_segments;
singular_query_segments : (s (name_segment | index_segment))*;
name_segment        : ('[' name_selector ']') |
                      ('.' member_name_shorthand);
index_segment       : '[' index_selector ']';
number              : (int_1 | ('-' '0')) ( frac )? ( exp )?; // decimal number
frac                : '.' DIGIT+;                  // decimal fraction
exp                 : ('E' | 'e') ( '-' | '+' )? DIGIT+;    // decimal exponent
function_name       : function_name_first function_name_char*;
function_name_first : LCALPHA;
function_name_char  : function_name_first | '_' | DIGIT;

function_expr       : function_name '(' s (function_argument
                         (s ',' s function_argument)*)? s ')';
function_argument   : literal |
                      filter_query | // (includes singular-query)
                      logical_expr |
                      function_expr;
segment             : child_segment | descendant_segment;
child_segment       : bracketed_selection |
                      ('.'
                       (WILDCARD_SELECTOR |
                        member_name_shorthand));

bracketed_selection : '[' s selector (s ',' s selector)* s ']';

member_name_shorthand : NAME_FIRST name_char*;
name_char           : NAME_FIRST | DIGIT;
descendant_segment  : ('.' '.') (bracketed_selection |
                            WILDCARD_SELECTOR |
                            member_name_shorthand);


comparisonOp
    : equalsOp | notEqualsOp
    | smallerThanOp | greaterThanOp
    | smallerThanOrEqualsOp | greaterThanOrEqualsOp
    ;

equalsOp: EQUALS_OP;
notEqualsOp: NOT_EQUALS_OP;
smallerThanOp: SMALLER_THAN_OP;
greaterThanOp: GREATHER_THAN_OP;
smallerThanOrEqualsOp: SMALLER_THAN_OR_EQUALS_OP;
greaterThanOrEqualsOp: GREATER_THAN_OR_EQUALS_OP;


SQUOTE: '\u0027';
DQUOTE: '\u0022';

TRUE_1                : 'true';                // true
FALSE_1               : 'false';             // false
NULL_1                : 'null';                // null
CURRENT_NODE_IDENTIFIER : '@';
LOGICAL_NOT_OP      : '!';               // logical NOT operator

DIGIT               : '\u0030'..'\u0039';              // 0-9
ALPHA               : '\u0041'..'\u005A' | '\u0061'..'\u007A';    // A-Z / a-z

NAME_FIRST          : ALPHA |
                      '_'   |
                      '\u0080'..'\uD7FF' |
                         // skip surrogate code points
                      '\uE000'..'\u{10FFFF}';

WILDCARD_SELECTOR   : '*';
LCALPHA             : '\u0061'..'\u007A';  // "a".."z"

EQUALS_OP: '==';
NOT_EQUALS_OP: '!=';
SMALLER_THAN_OP: '<';
GREATHER_THAN_OP: '>';
SMALLER_THAN_OR_EQUALS_OP: '<=';
GREATER_THAN_OR_EQUALS_OP: '>=';


B                   : '\u0020' |    // Space
                      '\u0009' |    // Horizontal tab
                      '\u000A' |    // Line feed or New line
                      '\u000D';      // Carriage return
ROOT_IDENTIFIER     : '$';

ESC                 : '\u005C';                           // \ backslash

UNESCAPED           : '\u0020'..'\u0021' |                      // see RFC 8259
                         // omit 0x22 "
                      '\u0023'..'\u0026' |
                         // omit 0x27 '
                      '\u0028'..'\u005B' |
                         // omit 0x5C \
                      '\u005D'..'\uD7FF' |
                         // skip surrogate code points
                      '\uE000'..'\u{10FFFF}';
NUMBERS_ZERO_UNTIL_SEVEN: [\u0030-\u0037];
DIGIT1              : '\u0031'..'\u0039';                    // 1-9 non-zero digit
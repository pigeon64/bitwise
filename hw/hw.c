#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>

#define MAX(x, y) ((x) >= (y) ? (x) : (y))

void *xrealloc(void *ptr, size_t num_bytes) {
    ptr = realloc(ptr, num_bytes);
    if (!ptr) {
        perror("xrealloc failed");
        exit(1);
    }
    return ptr;
}

void *xmalloc(size_t num_bytes) {
    void *ptr = malloc(num_bytes);
    if (!ptr) {
        perror("xmalloc failed");
        exit(1);
    }
    return ptr;
}

void fatal(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("FATAL: ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
    exit(1);
}

// Stretchy buffers, invented (?) by Sean Barrett

typedef struct BufHdr {
    size_t len;
    size_t cap;
    char buf[];
} BufHdr;

#define buf__hdr(b) ((BufHdr *)((char *)(b) - offsetof(BufHdr, buf)))
#define buf__fits(b, n) (buf_len(b) + (n) <= buf_cap(b))
#define buf__fit(b, n) (buf__fits((b), (n)) ? 0 : ((b) = buf__grow((b), buf_len(b) + (n), sizeof(*(b)))))

#define buf_len(b) ((b) ? buf__hdr(b)->len : 0)
#define buf_cap(b) ((b) ? buf__hdr(b)->cap : 0)
#define buf_end(b) ((b) + buf_len(b))
#define buf_free(b) ((b) ? (free(buf__hdr(b)), (b) = NULL) : 0)
#define buf_push(b, ...) (buf__fit((b), 1), (b)[buf__hdr(b)->len++] = (__VA_ARGS__))

void *buf__grow(const void *buf, size_t new_len, size_t elem_size) {
    assert(buf_cap(buf) <= (SIZE_MAX - 1)/2);
    size_t new_cap = MAX(1 + 2*buf_cap(buf), new_len);
    assert(new_len <= new_cap);
    assert(new_cap <= (SIZE_MAX - offsetof(BufHdr, buf))/elem_size);
    size_t new_size = offsetof(BufHdr, buf) + new_cap*elem_size;
    BufHdr *new_hdr;
    if (buf) {
        new_hdr = xrealloc(buf__hdr(buf), new_size);
    } else {
        new_hdr = xmalloc(new_size);
        new_hdr->len = 0;
    }
    new_hdr->cap = new_cap;
    return new_hdr->buf;
}

void buf_test() {
    int *buf = NULL;
    assert(buf_len(buf) == 0);
    int n = 1024;
    for (int i = 0; i < n; i++) {
        buf_push(buf, i);
    }
    assert(buf_len(buf) == n);
    for (int i = 0; i < buf_len(buf); i++) {
        assert(buf[i] == i);
    }
    buf_free(buf);
    assert(buf == NULL);
    assert(buf_len(buf) == 0);
}

typedef enum TokenKind {
    TOKEN_LASTCHAR = 127,
    TOKEN_LSHIFT,         // Left shift operator "<<"
    TOKEN_RSHIFT,         // Right shift operator ">>"
    TOKEN_INT             // Integer literal, value stored in Token.val
} TokenKind;

typedef struct Token {
    TokenKind kind;
    int val;
} Token;

Token token;
const char *stream;


void next_token() {
    char ch = *stream;
    bool isRightShift = true;
    switch (ch) {
    case '0': case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9': {
        int val = 0;
        do {
            val *= 10;
            val += ch - '0';
            ch = *(++stream);
        } while (isdigit(ch));

        token.kind = TOKEN_INT;
        token.val = val;
        break;
    }
    case '<':
        isRightShift = false;
        // fall-through
    case '>':
        if (stream[1] == ch) {
            token.kind = (isRightShift ? TOKEN_RSHIFT : TOKEN_LSHIFT);
            stream += 2;
            break;
        }
        // fall-through if we didn't get a matching '<' or '>'
    default:
        token.kind = ch;
        ++stream;
        break;
    }
}

void init_stream(const char *str) {
    stream = str;
    next_token();
}

void print_token(Token token) {
    switch (token.kind) {
    case TOKEN_INT:
        printf("TOKEN INT: %d\n", token.val);
        break;
    case TOKEN_LSHIFT:
        puts("TOKEN <<");
        break;
    case TOKEN_RSHIFT:
        puts("TOKEN >>");
        break;
    default:
        printf("TOKEN '%c'\n", token.kind);
        break;
    }
}

static inline bool is_token(TokenKind kind) {
    return token.kind == kind;
}

static inline bool match_token(TokenKind kind) {
    if (is_token(kind)) {
        next_token();
        return true;
    } else {
        return false;
    }
}

static inline bool expect_token(TokenKind kind) {
    if (is_token(kind)) {
        next_token();
        return true;
    } else {
        char buf[256];
        copy_token_kind_str(buf, sizeof(buf), kind);
        fatal("expected token %s, got %s", buf, temp_token_kind_str(token.kind));
        return false;
    }
}

#define assert_token(x) assert(match_token(x))
#define assert_token_int(x) assert(token.val == (x) && match_token(TOKEN_INT))
#define assert_token_eof() assert(is_token(0))

void lex_test() {
    const char *str = "234+994<<2>>33-2~1<>";
    init_stream(str);
    assert_token_int(234);
    assert_token('+');
    assert_token_int(994);
    assert_token(TOKEN_LSHIFT);
    assert_token_int(2);
    assert_token(TOKEN_RSHIFT);
    assert_token_int(33);
    assert_token('-');
    assert_token_int(2);
    assert_token('~');
    assert_token_int(1);
    assert_token('<');
    assert_token('>');
    assert_token_eof();
}

#undef assert_token_eof
#undef assert_token_int
#undef assert_token

#if 0

    expr3 = INT
    expr2 = [-~] expr2 | expr3
    expr1 = expr2 ([*/%&] expr2)*
    expr1 = expr2 (LSHIFT expr2)*
    expr1 = expr2 (RSHIFT expr2)*
    expr0 = expr1 ([+-|^] expr1)*
    expr  = expr0

#endif


typedef struct Expr {

    Token token;
    struct Expr *left;
    struct Expr *right;

} Expr;

Expr* parse_alloc(Expr* left, Expr *right) {
    Expr *expr = (Expr*)xmalloc(sizeof(Expr));
    expr->token = token;
    expr->left = left;
    expr->right = right;
    return expr;
}

//
// Frees all alloc'd symbols in the given tree
//
void parse_free(Expr *tree) {
    // free the left child if it exists
    if (tree->left) {
        parse_free(tree->left);
    }
    // free the right child if it exists
    if (tree->right) {
        parse_free(tree->right);
    }
    free(tree);
}

void parse_dump(Expr *tree) {
    Token t = tree->token;
    if (t.kind == TOKEN_INT) {
        printf("%d", t.val);
    } else {
        putchar('(');
        switch (t.kind) {
        case TOKEN_LSHIFT:
            printf("<< ");
            break;
        case TOKEN_RSHIFT:
            printf(">> ");
            break;
        default:
            printf("%c ", t.kind);
            break;
        }
        // L, R => (+ L R)
        // L    => (- L)
        //      => INT
        if (tree->left)
            parse_dump(tree->left);

        if (tree->right) {
            putchar(' ');
            parse_dump(tree->right);
        }

        putchar(')');
    }
}

Expr* parse_expr(void);

Expr* parse_expr3(void) {
    if (is_token(TOKEN_INT)) {
        Expr *expr = parse_alloc(NULL, NULL);
        next_token();
        return expr;
    } else {
        fatal("expected integer");
        return NULL;
    }
}

Expr* parse_expr2(void) {
    if (is_token('-') || is_token('~')) {
        Expr *expr = parse_alloc(NULL, NULL);
        next_token();
        expr->left = parse_expr2();
        return expr;
    } else {
        return parse_expr3();
    }
}

Expr* parse_expr1(void) {
    Expr *left = parse_expr2();
    while (is_token('*') || is_token('/') || is_token('%') || is_token('&')
        || is_token(TOKEN_LSHIFT) || is_token(TOKEN_RSHIFT)) {
        Expr *expr = parse_alloc(left, NULL);
        next_token();
        expr->right = parse_expr2();
        left = expr;
    }
    return left;
}

Expr* parse_expr0(void) {
    Expr *left = parse_expr1();
    while (is_token('+') || is_token('-') || is_token('|') || is_token('^')) {
        Expr *expr = parse_alloc(left, NULL);
        next_token();
        expr->right = parse_expr1();
        left = expr;
    }
    return left;
}

Expr* parse_expr(void) {
    return parse_expr0();
}


//
// Evaluate the given symbol tree
//
int eval(Expr *tree) {
    int left = (tree->left) ? eval(tree->left) : 0;
    int right = (tree->right) ? eval(tree->right) : 0;
    Token token = tree->token;
    switch (token.kind) {
    case TOKEN_INT:
        return token.val;
    case TOKEN_LSHIFT:
        return left << right;
    case TOKEN_RSHIFT:
        return left >> right;
    case '+':
        return left + right;
    case '-':
        if (tree->right == NULL)
            return -left; // negate operand
            // TODO: this if statement would not be necessary if the child expression
            // was stored in the right instead of the left since
            // left - right == 0 - right == -right
        else
            return left - right;
    case '|':
        return left | right;
    case '^':
        return left ^ right;
    case '*':
        return left * right;
    case '/':
        if (right == 0)
            fatal("cannot divide by 0");
        return left / right;
    case '%':
        return left % right;
    case '&':
        return left & right;
    case '~':
        return ~left;
    default:
        fatal("unknown operand");
        return 0;
    }
}

#if 0
    expr3 = INT | '(' expr ')' 
    expr2 = '-' expr2 | expr3
    expr1 = expr2 ([*/] expr2)*
    expr0 = expr1 ([+-] expr1)*
    expr = expr0


int parse_expr();

int parse_expr3() {
    if (is_token(TOKEN_INT)) {
        int val = token.val;
        next_token();
        return val;
    } else if (match_token('(')) {
        int val = parse_expr();
        expect_token(')');
        return val;
    } else {
        fatal("expected integer or (, got %s", temp_token_kind_str(token.kind));
        return 0;
    }
}

int parse_expr2() {
    if (match_token('-')) {
        return -parse_expr2();
    } else if (match_token('+')) {
        return parse_expr2();
    } else {
        return parse_expr3();
    }
}

int parse_expr1() {
    int val = parse_expr2();
    while (is_token('*') || is_token('/')) {
        char op = token.kind;
        next_token();
        int rval = parse_expr2();
        if (op == '*') {
            val *= rval;
        } else {
            assert(op == '/');
            assert(rval != 0);
            val /= rval;
        }
    }
    return val;
}

int parse_expr0() {
    int val = parse_expr1();
    while (is_token('+') || is_token('-')) {
        char op = token.kind;
        next_token();
        int rval = parse_expr1();
        if (op == '+') {
            val += rval;
        } else {
            assert(op == '-');
            val -= rval;
        }
    }
    return val;
}

int parse_expr() {
    return parse_expr0();
}

int parse_expr_str(const char *str) {
    init_stream(str);
    return parse_expr();
}

#define assert_expr(x) assert(parse_expr_str(#x) == (x))

void parse_test() {
    assert_expr(1);
    assert_expr((1));
    assert_expr(-+1);
    assert_expr(1-2-3);
    assert_expr(2*3+4*5);
    assert_expr(2*(3+4)*5);
    assert_expr(2+-3);
}

#undef assert_expr

#endif

void run_tests() {
    buf_test();
    lex_test();
    //parse_test();
}

int main(int argc, char **argv) {
    run_tests();

    init_stream("12*34+45/56+~25");
    //init_stream("1+2*4");
    Expr *sym = parse_expr();
    parse_dump(sym);
    printf(" = %d\n", eval(sym));
    parse_free(sym);
    return 0;
}


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>

void error(const char *msg) {
    fprintf(stderr, "Fatal error: %s\n", msg);
    exit(1);
}

void *mem_alloc(int size) {
    void *p = malloc(size); if (!p) error("Out of memory");
    return p;
}

void *mem_realloc(void *p, int size) {
    p = realloc(p, size); if (!p) error("Out of memory");
    return p;
}

void mem_dealloc(void *p) {
    if (p) free(p);
}

typedef struct TExpr {
    char **func_names;
    struct TExpr **func_values;
    int func_size, func_alloc;
    char **var_names;
    double *var_values;
    int var_size, var_alloc;
    unsigned char *code; int code_size, code_alloc;
    int stack_size;
} Expr;

static Expr *allocate_expression() {
    Expr *e = mem_alloc(sizeof(Expr));

    e->func_names = mem_alloc(sizeof(char *)*10);
    e->func_values = mem_alloc(sizeof(char *)*10);
    e->func_size = 0; e->func_alloc = 10;

    e->var_names = mem_alloc(sizeof(char *)*10);
    e->var_values = mem_alloc(sizeof(double)*10);
    e->var_size = 0; e->var_alloc = 10;

    e->code = mem_alloc(100);
    e->code_size = 0; e->code_alloc = 100;
    e->stack_size = 0;

    return e;
}

void emit_bytes(Expr *E, void *p, int size) {
    if (E->code_size + size > E->code_alloc) {
        int newalloc = E->code_alloc * 2;
        if (E->code_size + size > newalloc) newalloc = E->code_size + size;
        E->code = mem_realloc(E->code, newalloc);
        E->code_alloc = newalloc;
    }
    memcpy(E->code + E->code_size, p, size);
    E->code_size += size;
}

void emit(Expr *E, unsigned char op) {
    emit_bytes(E, &op, 1);
}

void deallocate_expression(Expr *e) {
    if (e) {
        for (int i=0; i<e->var_size; i++) mem_dealloc(e->var_names[i]);
        for (int i=0; i<e->func_size; i++) {
            mem_dealloc(e->func_names[i]);
            if (e->func_values[i] != e) deallocate_expression(e->func_values[i]);
        }
        mem_dealloc(e->var_names);
        mem_dealloc(e->var_values);
        mem_dealloc(e->func_names);
        mem_dealloc(e->func_values);
        mem_dealloc(e->code);
        mem_dealloc(e);
    }
}

void skip_spaces(const char **s) {
    for(;;) {
        while (**s == ' ' || **s == '\t' || **s == '\n' || **s == '\r') (*s)++;
        if (**s == '/' && *(*s + 1) == '/') {
            while (**s != '\0' && **s != '\n') (*s)++;
        } else {
            break;
        }
    }
}

#define op_drop      0x00
#define op_constant  0x01
#define op_assign    0x02
#define op_variable  0x03
#define op_neg       0x04
#define op_add       0x05
#define op_mul       0x06
#define op_sub       0x07
#define op_div       0x08
#define op_lt        0x09
#define op_le        0x0A
#define op_gt        0x0B
#define op_ge        0x0C
#define op_eq        0x0D
#define op_ne        0x0E
#define op_bitand    0x0F
#define op_bitor     0x10
#define op_bitxor    0x11
#define op_lsh       0x12
#define op_rsh       0x13
#define op_and       0x14
#define op_or        0x15
#define op_jmp       0x16
#define op_jfalse    0x17
#define op_fcall     0x18
#define op_halt      0x19

double eval_expression(Expr *E, double *args) {
    double *sp = alloca(E->stack_size * sizeof(double));
    unsigned char *code = E->code, *ip = code;
    if (args == NULL) args = E->var_values;
    #define FETCH(T_) ({ T_ x_; memcpy(&x_, ip, sizeof(x_)); ip += sizeof(x_); x_; })
    for(;;) {
        switch(*ip++) {
            case op_drop: sp--; continue;
            case op_constant: *sp++ = FETCH(double); continue;
            case op_assign: E->var_values[FETCH(int)] = sp[-1]; continue;
            case op_variable: *sp++ = args[FETCH(int)]; continue;
            case op_neg: sp[-1] = - sp[-1]; continue;
            case op_add: sp[-2] += sp[-1]; --sp; continue;
            case op_mul: sp[-2] *= sp[-1]; --sp; continue;
            case op_sub: sp[-2] -= sp[-1]; --sp; continue;
            case op_div: sp[-2] /= sp[-1]; --sp; continue;
            case op_lt: sp[-2] = sp[-2] < sp[-1]; --sp; continue;
            case op_le: sp[-2] = sp[-2] <= sp[-1]; --sp; continue;
            case op_gt: sp[-2] = sp[-2] > sp[-1]; --sp; continue;
            case op_ge: sp[-2] = sp[-2] >= sp[-1]; --sp; continue;
            case op_eq: sp[-2] = sp[-2] == sp[-1]; --sp; continue;
            case op_ne: sp[-2] = sp[-2] != sp[-1]; --sp; continue;
            case op_bitand: sp[-2] = (unsigned)sp[-2] & (unsigned)sp[-1]; --sp; continue;
            case op_bitor: sp[-2] = (unsigned)sp[-2] | (unsigned)sp[-1]; --sp; continue;
            case op_bitxor: sp[-2] = (unsigned)sp[-2] ^ (unsigned)sp[-1]; --sp; continue;
            case op_lsh: sp[-2] = (unsigned)sp[-2] << (unsigned)sp[-1]; --sp; continue;
            case op_rsh: sp[-2] = (unsigned)sp[-2] >> (unsigned)sp[-1]; --sp; continue;
            case op_and: sp[-2] = sp[-2]!=0 && sp[-1]!=0; --sp; continue;
            case op_or: sp[-2] = sp[-2]!=0 || sp[-1]!=0; --sp; continue;
            case op_jmp: { int addr = FETCH(int); ip = code+addr; } continue;
            case op_jfalse: { int addr = FETCH(int); if (sp[-1] == 0) ip = code+addr; } continue;
            case op_fcall: {
                Expr *f = E->func_values[FETCH(int)]; sp -= f->var_size;
                *sp = eval_expression(f, sp); sp++;
                continue;
            }
            case op_halt: return sp[-1];
        }
    }
    #undef FETCH
    error("Internal error; unreachable code");
    return 0;
}

typedef struct TOperator {
    const char *name;
    int level, rassoc;
    unsigned char opcode;
} Operator;

static Operator ops[] = {
    { "*", 1, 0, op_mul }, { "/", 1, 0, op_div },
    { "+", 2, 0, op_add }, { "-", 2, 0, op_sub },
    { "&", 3, 0, op_bitand },
    { "|", 4, 0, op_bitor }, { "^", 4, 0, op_bitxor },
    { "<<", 5, 0, op_lsh }, { ">>", 5, 0, op_rsh },
    { "<", 6, 0, op_lt }, { "<=", 6, 0, op_le }, { ">", 6, 0, op_gt }, { ">=", 6, 0, op_ge },
       { "=", 6, 0, op_eq }, { "!=", 6, 0, op_ne },
    { "&&", 7, 0, op_and },
    { "||", 8, 0, op_or },
    { NULL },
};

#define MAX_LEVEL 9

static int num(int c) {
    return c >= '0' && c <= '9';
}

static int alpha(int c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static int alphanum(int c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||  c == '_';
}

static void parse(Expr *E, const char **s, int level, int sp) {
    if (level == 0) {
        skip_spaces(s);
        if (**s == '{') {
            ++(*s);
            int first = 1;
            for(;;) {
                skip_spaces(s);
                if (**s == '}') break;
                if (!first) emit(E, op_drop);
                first = 0;
                parse(E, s, MAX_LEVEL, sp);
                skip_spaces(s);
                if (**s == ';') ++(*s);
                else if (**s != '}') error("';' or '}' expected");
            }
            if (first) error("At least an expression is required in a block");
            ++(*s);
            return;
        } else if (**s == '(') {
            ++(*s);
            parse(E, s, MAX_LEVEL, sp);
            skip_spaces(s);
            if (**s != ')') error("')' expected");
            ++(*s);
            return;
        } else if (**s == '-') {
            ++(*s);
            parse(E, s, 0, sp);
            emit(E, op_neg);
            return;
        } else if (num(**s) || **s == '.') {
            const char *s0 = *s;
            int ok = 0;
            while (num(**s)) { ok=1; ++(*s); }
            if (**s == '.') {
                ++(*s);
                while (num(**s)) { ok=1; ++(*s); }
            }
            if (!ok) error("Digits required either before or after decimal point");
            if (**s == 'e' || **s == 'E') {
                ++(*s);
                if (**s == '+' || **s == '-') ++(*s);
                if (!num(**s)) error("Digits required for exponent");
                while (num(**s)) ++(*s);
            }
            char *e = NULL;
            double v = strtod(s0, &e);
            if (e != *s) error("Invalid number");
            emit(E, op_constant);
            emit_bytes(E, &v, sizeof(v));
            if (sp+1 > E->stack_size) E->stack_size = sp+1;
            return;
        } else if (alpha(**s)) {
            const char *s0 = *s;
            while (alphanum(**s)) ++(*s);
            int n = *s - s0, i = 0;
            if (n == 5 && strncmp(s0, "while", 5) == 0) {
                skip_spaces(s);
                if (**s != '(') error("'(' expected after 'while' keyword");
                int test_addr = E->code_size;
                parse(E, s, 0, sp);
                emit(E, op_jfalse);
                int jquit = E->code_size;
                emit_bytes(E, &jquit, sizeof(int));
                skip_spaces(s);
                if (**s != '{') error("'{' expected");
                emit(E, op_drop);
                parse(E, s, 0, sp);
                emit(E, op_drop);
                emit(E, op_jmp);
                emit_bytes(E, &test_addr, sizeof(test_addr));
                memcpy(E->code + jquit, &E->code_size, sizeof(E->code_size));
                return;
            } else if (n == 2 && strncmp(s0, "if", 2) == 0) {
                skip_spaces(s);
                if (**s != '(') error("'(' expected after 'if' keyword");
                parse(E, s, 0, sp);
                emit(E, op_jfalse);
                int jfalse = E->code_size; emit_bytes(E, &jfalse, sizeof(int));
                skip_spaces(s);
                if (**s != '{') error("'{' expected");
                emit(E, op_drop);
                parse(E, s, 0, sp);
                emit(E, op_jmp);
                int jquit = E->code_size; emit_bytes(E, &jquit, sizeof(int));
                memcpy(E->code+jfalse, &E->code_size, sizeof(int));
                skip_spaces(s);
                if (strncmp(*s, "else", 4) == 0 && !alphanum(*(*s+4))) {
                    (*s) += 4;
                    skip_spaces(s);
                    if (**s != '{') error("'{' expected");
                    emit(E, op_drop);
                    parse(E, s, 0, sp);
                } else {
                    double v = 0; emit(E, op_constant); emit_bytes(E, &v, sizeof(v));
                }
                memcpy(E->code+jquit, &E->code_size, sizeof(int));
                return;
            }
            if (**s == '(') {
                while (i<E->func_size && (strncmp(E->func_names[i], s0, n) != 0 || E->func_names[i][n] != '\0')) {
                    ++i;
                }
                if (i == E->func_size) {
                    for (int i=0,n=*s-s0; i<n; i++) fputc(s0[i], stderr);
                    fprintf(stderr, ": ");
                    error("Unknown function");
                }
                (*s)++;
                int np = 0;
                while(np < E->func_values[i]->var_size) {
                    skip_spaces(s);
                    if (**s == ')') error("Wrong number of parameters for function call");
                    parse(E, s, MAX_LEVEL, sp+np);
                    skip_spaces(s);
                    if (**s == ',') (*s)++; else if (**s != ')') error("',' or ')' expected");
                    np++;
                }
                skip_spaces(s); if (**s != ')') error("')' expected");
                (*s)++;
                emit(E, op_fcall);
                emit_bytes(E, &i, sizeof(int));
                return;
            }
            while (i<E->var_size && (strncmp(E->var_names[i], s0, n) != 0 || E->var_names[i][n] != '\0')) {
                ++i;
            }
            if (i == E->var_size) {
                if (E->var_size == E->var_alloc) {
                    int newalloc = E->var_alloc*2;
                    E->var_names = mem_realloc(E->var_names, newalloc*sizeof(const char *));
                    E->var_values = mem_realloc(E->var_values, newalloc*sizeof(double));
                    E->var_alloc = newalloc;
                }
                E->var_names[i] = mem_alloc(n+1);
                memcpy(E->var_names[i], s0, n);
                E->var_names[i][n] = '\0';
                E->var_values[i] = 0;
                E->var_size++;
            }
            skip_spaces(s);
            if (**s == ':' && *(*s+1) == '=') {
                *s += 2;
                parse(E, s, MAX_LEVEL, sp);
                emit(E, op_assign);
                emit_bytes(E, &i, sizeof(int));
            } else {
                emit(E, op_variable);
                emit_bytes(E, &i, sizeof(int));
                if (sp+1 > E->stack_size) E->stack_size = sp+1;
            }
            return;
        } else {
            fprintf(stderr, "---> '%s'\n", *s);
            error("Expression expected");
        }
    }
    parse(E, s, level-1, sp);
    for(;;) {
        skip_spaces(s);
        int op_index = -1, op_sz = -1;
        for (int i=0; ops[i].name; i++) {
            int sz = strlen(ops[i].name);
            if (strncmp(ops[i].name, *s, sz) == 0 && (op_index == -1 || op_sz < sz)) {
                op_index = i; op_sz = sz;
            }
        }
        if (op_index == -1 || ops[op_index].level != level) break;
        (*s) += op_sz;
        parse(E, s, (ops[op_index].rassoc ? level : level-1), sp+1);
        emit(E, ops[op_index].opcode);
    }
}

Expr *parse_expression(const char **s) {
    Expr *E = allocate_expression();
    skip_spaces(s);
    while (strncmp(*s, "def", 3) == 0 && !alphanum((*s)[3])) {
        (*s) += 3;
        skip_spaces(s);
        if (!alpha(**s)) error("Function name expected");
        const char *s0 = *s;
        while (alphanum(**s)) (*s)++;
        int n = *s - s0;
        int i = 0;
        while (i < E->func_size && (strncmp(E->func_names[i], s0, n) != 0 || E->func_names[i][n] != '\0')) i++;
        if (i < E->func_size) error("Duplicated function name");
        if (E->func_size == E->func_alloc) {
            int nalloc = E->func_alloc*2;
            E->func_names = mem_realloc(E->func_names, nalloc*sizeof(char *));
            E->func_values = mem_realloc(E->func_values, nalloc*sizeof(Expr *));
            E->func_alloc = nalloc;
        }
        E->func_names[i] = mem_alloc(n+1);
        memcpy(E->func_names[i], s0, n);
        E->func_names[i][n] = '\0';
        Expr *f = E->func_values[i] = allocate_expression();
        E->func_size++;
        f->func_names[0] = mem_alloc(n+1);
        memcpy(f->func_names[0], s0, n);
        f->func_names[0][n] = '\0';
        f->func_values[0] = f;
        f->func_size++;
        skip_spaces(s);
        if (**s != '(') error("'(' expected");
        (*s)++;
        for(;;) {
            skip_spaces(s);
            if (**s == ')') break;
            if (!alpha(**s)) error("Parameter name expected");
            const char *s0 = *s;
            while (alphanum(**s)) (*s)++;
            int n = *s - s0;
            int j = 0;
            while (j < f->var_size && (strncmp(f->var_names[j], s0, n) != 0 || f->var_names[j][n] != '\0')) j++;
            if (j < f->var_size) error("Duplicated parameter name");
            if (f->var_size == f->var_alloc) {
                int nalloc = f->var_alloc*2;
                f->var_names = mem_realloc(f->var_names, nalloc*sizeof(char *));
                f->var_values = mem_realloc(f->var_values, nalloc*sizeof(double));
                f->var_alloc = nalloc;
            }
            f->var_size++;
            f->var_names[j] = mem_alloc(n+1);
            memcpy(f->var_names[j], s0, n);
            f->var_names[j][n] = '\0';
            f->var_values[j] = 0;
            skip_spaces(s);
            if (**s == ',') (*s)++; else if (**s != ')') error("',' or ')' expected");
        }
        (*s)++;
        skip_spaces(s);
        if (**s != '{') error("'{' expected");
        parse(f, s, 0, 0);
        emit(f, op_halt);
    }
    parse(E, s, MAX_LEVEL, 0);
    emit(E, op_halt);
    return E;
}

int main(int argc, const char *argv[]) {
    for (int i=1; i<argc; i++) {
        printf("Expression text '%s'\n", argv[i]);
        const char *s = argv[i];
        Expr *e = parse_expression(&s);
        skip_spaces(&s);
        if (*s != '\0') error("Extra characters at end of expression");
        printf("Value --> %.18g\n", eval_expression(e, NULL));
        deallocate_expression(e);
    }
    return 0;
}
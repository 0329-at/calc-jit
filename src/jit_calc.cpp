#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <print>
#include <stack>
#include <map>
#include <stdexcept>
#include <iomanip>
#include <sys/mman.h>

using namespace std;

// Token类型
enum TokenType { NUMBER, OPERATOR, LPAREN, RPAREN, UNARY_OP };

struct Token {
    TokenType type;
    string value;
    Token(TokenType t, const string& v) : type(t), value(v) {}
};

// AST节点
struct ASTNode {
    string value;
    TokenType type;
    ASTNode* left;
    ASTNode* right;
    
    ASTNode(string v, TokenType t) 
        : value(v), type(t), left(nullptr), right(nullptr) {}
};

// JIT结果
struct JitResult {
    using FuncType = double(*)();
    FuncType func;
    void* addr;
    size_t size;
    vector<uint8_t> machine_code;
};

// 运算符优先级
map<string, int> op_precedence = {
    {"+", 1}, {"-", 1},
    {"*", 2}, {"/", 2},
    {"u-", 3} // 一元负号
};

// 辅助函数：打印AST
void print_ast(ASTNode* node, int indent = 0) {
    if (!node) return;
    
    std::print("{}[", string(indent, ' '));
    switch(node->type) {
        case NUMBER: std::print("NUM "); break;
        case OPERATOR: std::print("OP  "); break;
        case UNARY_OP: std::print("UOP "); break;
        default: std::print("    ");
    }
    std::println("{}]", node->value);
    
    print_ast(node->left, indent + 2);
    print_ast(node->right, indent + 2);
}

// 增强词法分析
vector<Token> tokenize(const string& expr) {
    vector<Token> tokens;
    string num;
    bool expect_operand = true;

    for (size_t i = 0; i < expr.size(); ++i) {
        char c = expr[i];
        if (isspace(c)) continue;

        if (isdigit(c) || c == '.' || (c == '-' && expect_operand)) {
            // 处理数字
            num += c;
            while (i+1 < expr.size() && 
                  (isdigit(expr[i+1]) || expr[i+1] == '.')) {
                num += expr[++i];
            }
            tokens.emplace_back(NUMBER, num);
            num.clear();
            expect_operand = false;
        } else if (c == '(') {
            tokens.emplace_back(LPAREN, "(");
            expect_operand = true;
        } else if (c == ')') {
            tokens.emplace_back(RPAREN, ")");
            expect_operand = false;
        } else if (string("+-*/").find(c) != string::npos) {
            if (c == '-' && expect_operand) {
                tokens.emplace_back(UNARY_OP, "u-");
            } else {
                tokens.emplace_back(OPERATOR, string(1, c));
            }
            expect_operand = true;
        } else {
            throw runtime_error("无效字符: " + string(1, c));
        }
    }
    return tokens;
}

// 构建AST
ASTNode* build_ast(const vector<Token>& tokens) {
    stack<ASTNode*> value_stack;
    stack<pair<string, int>> op_stack;

    auto apply_operator = [&]() {
        auto [op, prec] = op_stack.top();
        op_stack.pop();

        if (op == "u-") {
            ASTNode* node = new ASTNode(op, UNARY_OP);
            node->right = value_stack.top();
            value_stack.pop();
            value_stack.push(node);
        } else {
            ASTNode* node = new ASTNode(op, OPERATOR);
            node->right = value_stack.top();
            value_stack.pop();
            node->left = value_stack.top();
            value_stack.pop();
            value_stack.push(node);
        }
    };

    for (const auto& token : tokens) {
        switch(token.type) {
            case NUMBER:
                value_stack.push(new ASTNode(token.value, NUMBER));
                break;
            case LPAREN:
                op_stack.emplace("(", 0);
                break;
            case RPAREN: {
                while (!op_stack.empty() && op_stack.top().first != "(") {
                    apply_operator();
                }
                if (op_stack.empty()) throw runtime_error("括号不匹配");
                op_stack.pop();
                break;
            }
            case OPERATOR:
            case UNARY_OP: {
                int prec = (token.value == "u-") ? 3 : op_precedence[token.value];
                while (!op_stack.empty() && 
                      op_stack.top().first != "(" &&
                      prec <= op_stack.top().second) {
                    apply_operator();
                }
                op_stack.emplace(token.value, prec);
                break;
            }
        }
    }

    while (!op_stack.empty()) {
        apply_operator();
    }

    return value_stack.top();
}

// 代码生成
void generate_code(ASTNode* node, vector<uint8_t>& code) {
    if (!node) return;

    if (node->type == NUMBER) {
        double num = stod(node->value);
        // mov rax, imm64
        code.push_back(0x48);
        code.push_back(0xB8);
        uint64_t bytes;
        memcpy(&bytes, &num, sizeof(num));
        for (int i = 0; i < 8; ++i) {
            code.push_back(bytes >> (i * 8) & 0xFF);
        }
        // movq xmm0, rax
        code.insert(code.end(), {0x66, 0x48, 0x0F, 0x6E, 0xC0});
        // sub rsp, 8
        code.insert(code.end(), {0x48, 0x83, 0xEC, 0x08});
        // movsd [rsp], xmm0
        code.insert(code.end(), {0xF2, 0x0F, 0x11, 0x04, 0x24});
        return;
    }

    generate_code(node->left, code);
    generate_code(node->right, code);

    // 生成操作符代码
    code.insert(code.end(), {0xF2, 0x0F, 0x10, 0x04, 0x24}); // movsd xmm0, [rsp]
    code.insert(code.end(), {0x48, 0x83, 0xC4, 0x08});       // add rsp,8
    code.insert(code.end(), {0xF2, 0x0F, 0x10, 0x0C, 0x24}); // movsd xmm1, [rsp]
    code.insert(code.end(), {0x48, 0x83, 0xC4, 0x08});       // add rsp,8

    char op = node->value[0];
    switch(op) {
        case '+': 
            code.insert(code.end(), {0xF2, 0x0F, 0x58, 0xC1}); // addsd xmm0, xmm1
            break;
        case '-':
            code.insert(code.end(), {0xF2, 0x0F, 0x5C, 0xC8}); // subsd xmm1, xmm0 → xmm1 - xmm0
            code.insert(code.end(), {0x66, 0x48, 0x0F, 0x28, 0xC1}); // movapd xmm0, xmm1
            break;
        case '*':
            code.insert(code.end(), {0xF2, 0x0F, 0x59, 0xC1}); // mulsd xmm0, xmm1
            break;
        case '/':
            code.insert(code.end(), {0xF2, 0x0F, 0x5E, 0xC8}); // divsd xmm1, xmm0 → xmm1 / xmm0
            code.insert(code.end(), {0x66, 0x48, 0x0F, 0x28, 0xC1}); // movapd xmm0, xmm1
            break;
        case 'u':
            code.insert(code.end(), {0xF2, 0x0F, 0x57, 0xC9}); // xorpd xmm1, xmm1
            code.insert(code.end(), {0xF2, 0x0F, 0x5C, 0xC1}); // subsd xmm0, xmm1
            break;
    }

    code.insert(code.end(), {0x48, 0x83, 0xEC, 0x08});       // sub rsp,8
    code.insert(code.end(), {0xF2, 0x0F, 0x11, 0x04, 0x24}); // movsd [rsp], xmm0
}

// 分配可执行内存
void* allocate_executable_memory(size_t size) {
    void* ptr = mmap(nullptr, size, PROT_READ|PROT_WRITE|PROT_EXEC, 
                    MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) throw runtime_error("内存分配失败");
    return ptr;
}

// 显示机器码
void print_machine_code(const vector<uint8_t>& code) {
    std::println("机器码 ({} 字节):", code.size());
    for (size_t i = 0; i < code.size(); ++i) {
        if (i % 8 == 0) cout << "\n0x" << setw(4) << setfill('0') << hex << i << ": ";
        cout << setw(2) << setfill('0') << hex << (int)code[i] << " ";
    }
    cout << dec << endl << endl;
}

JitResult compile(const string& expr) {
    // 词法分析和AST构建
    auto tokens = tokenize(expr);
    ASTNode* ast = build_ast(tokens);
    
    std::println("抽象语法树:");
    print_ast(ast);
    std::println();

    // 生成机器码
    vector<uint8_t> code;
    generate_code(ast, code);
    code.insert(code.end(), {0xF2, 0x0F, 0x10, 0x04, 0x24}); // 加载结果
    code.insert(code.end(), {0x48, 0x83, 0xC4, 0x08});       // 清理栈
    code.push_back(0xC3); // ret

    print_machine_code(code);

    // 分配可执行内存
    size_t size = code.size();
    void* mem = allocate_executable_memory(size);
    memcpy(mem, code.data(), size);

    return {reinterpret_cast<JitResult::FuncType>(mem), mem, size, code};
}

int main(int argc, const char *argv[]) {
    string expr;

    while (1) {
        std::print("输入表达式: ");
        getline(cin, expr);

        try {
            JitResult result = compile(expr);
            std::println("计算结果: {}", result.func());
            munmap(result.addr, result.size);
        } catch (const exception& e) {
            std::print("错误: {}", e.what());
        }
        std::println();
    }

    return 0;
}
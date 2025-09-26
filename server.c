#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <unistd.h>
#include <signal.h>

// 调试宏定义
#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) \
    do { \
        fprintf(stderr, "[DEBUG] %s:%d:%s(): " fmt, \
                __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
        fflush(stderr); \
    } while (0)
#else
#define DEBUG_PRINT(fmt, ...) do {} while (0)
#endif

// HTML 页面内容
const char* index_html = 
"<!DOCTYPE html>"
"<html>"
"<head>"
"    <title>字符串提交</title>"
"    <meta charset=\"UTF-8\">"
"    <style>"
"        body { font-family: Arial, sans-serif; margin: 40px; }"
"        .container { max-width: 500px; margin: 0 auto; }"
"        .form-group { margin-bottom: 20px; }"
"        label { display: block; margin-bottom: 5px; font-weight: bold; }"
"        input[type=\"text\"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }"
"        button { background-color: #4CAF50; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }"
"        button:hover { background-color: #45a049; }"
"        .result { margin-top: 20px; padding: 10px; background-color: #f5f5f5; border-radius: 4px; }"
"    </style>"
"</head>"
"<body>"
"    <div class=\"container\">"
"        <h1>字符串提交示例</h1>"
"        <form id=\"stringForm\" method=\"POST\">"
"            <div class=\"form-group\">"
"                <label for=\"inputString\">请输入字符串:</label>"
"                <input type=\"text\" id=\"inputString\" name=\"inputString\" required>"
"            </div>"
"            <button type=\"submit\">提交</button>"
"        </form>"
"        <div id=\"result\" class=\"result\"></div>"
"    </div>"
"    <script>"
"        document.getElementById('stringForm').addEventListener('submit', function(e) {"
"            e.preventDefault();"
"            const formData = new FormData(this);"
"            "
"            fetch('/submit', {"
"                method: 'POST',"
"                body: formData"
"            })"
"            .then(response => response.text())"
"            .then(data => {"
"                document.getElementById('result').innerHTML = '<strong>服务器响应:</strong> ' + data;"
"            })"
"            .catch(error => {"
"                document.getElementById('result').innerHTML = '<strong>错误:</strong> ' + error;"
"            });"
"        });"
"    </script>"
"</body>"
"</html>";

// 处理根路径请求
void root_handler(struct evhttp_request *req, void *arg) {
    DEBUG_PRINT("处理根路径请求\n");
    
    struct evbuffer *buf = evbuffer_new();
    if (!buf) {
        DEBUG_PRINT("创建缓冲区失败\n");
        evhttp_send_error(req, HTTP_INTERNAL, "Failed to create buffer");
        return;
    }
    
    // 设置 HTTP 头
    evhttp_add_header(evhttp_request_get_output_headers(req), 
                     "Content-Type", "text/html; charset=UTF-8");
    
    // 写入 HTML 内容
    evbuffer_add_printf(buf, "%s", index_html);
    
    // 发送响应
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
    
    DEBUG_PRINT("根路径请求处理完成\n");
}

// URL 解码函数
char* url_decode(const char* src) {
    DEBUG_PRINT("解码 URL: %s\n", src);
    
    size_t src_len = strlen(src);
    char* decoded = malloc(src_len + 1);
    if (!decoded) {
        DEBUG_PRINT("内存分配失败\n");
        return NULL;
    }
    
    char* dst = decoded;
    while (*src) {
        if (*src == '%' && src[1] && src[2]) {
            char hex[3] = {src[1], src[2], '\0'};
            *dst++ = (char)strtol(hex, NULL, 16);
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
    
    DEBUG_PRINT("解码结果: %s\n", decoded);
    return decoded;
}

// 处理提交请求
void submit_handler(struct evhttp_request *req, void *arg) {
    DEBUG_PRINT("处理提交请求\n");
    
    struct evbuffer *buf = evbuffer_new();
    if (!buf) {
        DEBUG_PRINT("创建缓冲区失败\n");
        evhttp_send_error(req, HTTP_INTERNAL, "Failed to create buffer");
        return;
    }
    
    // 检查请求方法
    if (evhttp_request_get_command(req) != EVHTTP_REQ_POST) {
        DEBUG_PRINT("不支持的请求方法: %d\n", evhttp_request_get_command(req));
        evhttp_send_error(req, HTTP_BADMETHOD, "Only POST method is supported");
        evbuffer_free(buf);
        return;
    }
    
    // 读取 POST 数据
    struct evbuffer *input_buf = evhttp_request_get_input_buffer(req);
    size_t len = evbuffer_get_length(input_buf);
    
    DEBUG_PRINT("接收到 %zu 字节的 POST 数据\n", len);
    
    if (len > 0) {
        char *post_data = malloc(len + 1);
        if (!post_data) {
            DEBUG_PRINT("内存分配失败\n");
            evhttp_send_error(req, HTTP_INTERNAL, "Memory allocation failed");
            evbuffer_free(buf);
            return;
        }
        
        evbuffer_copyout(input_buf, post_data, len);
        post_data[len] = '\0';
        
        DEBUG_PRINT("原始 POST 数据: %s\n", post_data);
        
        // 解析表单数据
        char *input_string = NULL;
        char *decoded_string = NULL;
        
        char *token = strtok(post_data, "&");
        while (token != NULL) {
            DEBUG_PRINT("解析参数: %s\n", token);
            
            if (strncmp(token, "inputString=", 12) == 0) {
                input_string = token + 12;
                decoded_string = url_decode(input_string);
                break;
            }
            token = strtok(NULL, "&");
        }
        
        // 设置响应头
        evhttp_add_header(evhttp_request_get_output_headers(req), 
                         "Content-Type", "text/plain; charset=UTF-8");
        
        if (decoded_string && strlen(decoded_string) > 0) {
            DEBUG_PRINT("收到字符串: %s\n", decoded_string);
            printf("服务器日志: 收到字符串 - \"%s\"\n", decoded_string);
            evbuffer_add_printf(buf, "服务器已收到您的字符串: \"%s\"", decoded_string);
            free(decoded_string);
        } else {
            DEBUG_PRINT("未接收到有效的字符串\n");
            evbuffer_add_printf(buf, "错误：未接收到有效的字符串");
        }
        
        free(post_data);
    } else {
        DEBUG_PRINT("请求体为空\n");
        evbuffer_add_printf(buf, "错误：请求体为空");
    }
    
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
    
    DEBUG_PRINT("提交请求处理完成\n");
}

// 通用错误处理
void generic_handler(struct evhttp_request *req, void *arg) {
    DEBUG_PRINT("处理未找到的路径: %s\n", evhttp_request_get_uri(req));
    
    struct evbuffer *buf = evbuffer_new();
    if (!buf) {
        evhttp_send_error(req, HTTP_INTERNAL, "Failed to create buffer");
        return;
    }
    
    evbuffer_add_printf(buf, "404 - 页面未找到");
    evhttp_send_reply(req, HTTP_NOTFOUND, "Not Found", buf);
    evbuffer_free(buf);
}

// 信号处理函数
void signal_handler(int sig) {
    DEBUG_PRINT("接收到信号 %d\n", sig);
    printf("接收到信号 %d，正在关闭服务器...\n", sig);
    exit(0);
}

int main(int argc, char *argv[]) {
    DEBUG_PRINT("启动 HTTP 服务器\n");
    
    struct event_base *base;
    struct evhttp *http;
    struct evhttp_bound_socket *handle;
    
    unsigned short port = 8080;
    
    // 解析命令行参数
    if (argc > 1) {
        port = atoi(argv[1]);
        if (port == 0) {
            fprintf(stderr, "无效的端口号: %s\n", argv[1]);
            return 1;
        }
    }
    
    DEBUG_PRINT("使用端口: %d\n", port);
    
    // 创建 event base
    base = event_base_new();
    if (!base) {
        fprintf(stderr, "创建 event base 失败\n");
        return 1;
    }
    
    DEBUG_PRINT("event base 创建成功\n");
    
    // 创建 HTTP 服务器
    http = evhttp_new(base);
    if (!http) {
        fprintf(stderr, "创建 HTTP 服务器失败\n");
        return 1;
    }
    
    DEBUG_PRINT("HTTP 服务器创建成功\n");
    
    // 设置请求处理回调
    evhttp_set_cb(http, "/", root_handler, NULL);
    evhttp_set_cb(http, "/submit", submit_handler, NULL);
    evhttp_set_gencb(http, generic_handler, NULL);
    
    DEBUG_PRINT("请求处理器设置完成\n");
    
    // 绑定到端口
    handle = evhttp_bind_socket_with_handle(http, "0.0.0.0", port);
    if (!handle) {
        fprintf(stderr, "绑定到端口 %d 失败\n", port);
        return 1;
    }
    
    DEBUG_PRINT("端口绑定成功\n");
    
    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("HTTP 服务器启动成功，监听端口: %d\n", port);
    printf("访问 http://localhost:%d 来测试\n", port);
    printf("按 Ctrl+C 退出\n");
    
#ifdef DEBUG
    printf("=== 调试模式已启用 ===\n");
#endif
    
    // 进入事件循环
    DEBUG_PRINT("开始事件循环\n");
    event_base_dispatch(base);
    
    // 清理资源
    DEBUG_PRINT("清理资源\n");
    evhttp_free(http);
    event_base_free(base);
    
    DEBUG_PRINT("服务器退出\n");
    return 0;
}
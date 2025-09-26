#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/wait.h>
#include <errno.h>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h> // 用于 rotating_logger_mt
#include <filesystem> // 用于创建日志目录（C++17）

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

// 脚本路径配置
#define PROCESS_SCRIPT "./getauth.sh"
#define INDEX_HTML "index.html"

// HTML 页面内容 - 简化版本，避免可能的格式问题
// 在服务器代码中添加文件读取函数
char* read_file_contents(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        DEBUG_PRINT("无法打开文件: %s\n", filename);
        return NULL;
    }
    
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char* content = static_cast<char*>(malloc(length + 1));
    if (!content) {
        fclose(file);
        return NULL;
    }
    
    auto size_read = fread(content, 1, length, file);
    if (size_read != length) {
        DEBUG_PRINT("读取文件 %s 时出错: %s\n", filename, strerror(errno));
        free(content);
        fclose(file);
        return NULL;
    }
    content[length] = '\0';
    
    fclose(file);
    return content;
}

// 处理根路径请求
void root_handler(struct evhttp_request *req, void *arg) {
    DEBUG_PRINT("处理根路径请求\n");
    
    // 添加 CORS 头，避免跨域问题
    struct evkeyvalq* headers = evhttp_request_get_output_headers(req);
    evhttp_add_header(headers, "Content-Type", "text/html; charset=UTF-8");
    evhttp_add_header(headers, "Access-Control-Allow-Origin", "*");
    evhttp_add_header(headers, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    evhttp_add_header(headers, "Access-Control-Allow-Headers", "Content-Type");
    
    struct evbuffer *buf = evbuffer_new();
    if (!buf) {
        DEBUG_PRINT("创建缓冲区失败\n");
        evhttp_send_error(req, HTTP_INTERNAL, "Failed to create buffer");
        return;
    }
    
       // 从文件读取HTML内容
    char* html_content = read_file_contents(INDEX_HTML);
    if (!html_content) {
        // 如果文件读取失败，使用备用内容
        html_content = strdup("<html><body><h1>错误：无法加载页面</h1></body></html>");
    }

    evbuffer_add_printf(buf, "%s", html_content);
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
    
    DEBUG_PRINT("根路径请求处理完成\n");
}

// 处理 OPTIONS 请求（CORS 预检）
void options_handler(struct evhttp_request *req, void *arg) {
    DEBUG_PRINT("处理 OPTIONS 请求\n");
    
    struct evkeyvalq* headers = evhttp_request_get_output_headers(req);
    evhttp_add_header(headers, "Access-Control-Allow-Origin", "*");
    evhttp_add_header(headers, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    evhttp_add_header(headers, "Access-Control-Allow-Headers", "Content-Type");
    evhttp_add_header(headers, "Access-Control-Max-Age", "86400");
    
    evhttp_send_reply(req, HTTP_OK, "OK", NULL);
}

// URL 解码函数
char* url_decode(const char* src) {
    if (!src) return NULL;
    
    DEBUG_PRINT("解码 URL: %s\n", src);
    
    size_t src_len = strlen(src);
    char* decoded = static_cast<char*>(malloc(src_len + 1));
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

// 获取 Content-Type 头
const char* get_content_type(struct evhttp_request *req) {
    struct evkeyvalq* headers = evhttp_request_get_input_headers(req);
    const char* content_type = evhttp_find_header(headers, "Content-Type");
    DEBUG_PRINT("Content-Type: %s\n", content_type ? content_type : "NULL");
    return content_type;
}

// 安全的字符串复制函数
char* safe_strdup(const char* str) {
    if (!str) return NULL;
    return strdup(str);
}

// 调用外部脚本处理字符串
char* call_process_script(const char* input_string) {
    DEBUG_PRINT("调用处理脚本: %s, 输入: %s\n", PROCESS_SCRIPT, input_string);
    
    // 检查脚本是否存在且可执行
    if (access(PROCESS_SCRIPT, X_OK) != 0) {
        DEBUG_PRINT("脚本不存在或不可执行: %s, 错误: %s\n", PROCESS_SCRIPT, strerror(errno));
        char cmd[256] = {0};
        
        snprintf(cmd, sizeof(cmd), "%s \"%s\"", PROCESS_SCRIPT, input_string);
        // 创建默认脚本
        FILE* script_file = fopen(PROCESS_SCRIPT, "w");
        if (script_file) {
            fprintf(script_file, "#!/bin/bash\n");
            fprintf(script_file, "echo \"处理脚本被调用，输入参数: $1\"\n");
            fprintf(script_file, "echo \"字符串长度: ${#1}\"\n");
            fprintf(script_file, "echo \"当前时间: $(date)\"\n");
            fclose(script_file);
            chmod(PROCESS_SCRIPT, 0755);
            DEBUG_PRINT("已创建默认脚本: %s\n", PROCESS_SCRIPT);
        } else {
            DEBUG_PRINT("创建默认脚本失败: %s\n", strerror(errno));
            return safe_strdup("警告：使用内置处理（脚本创建失败）");
        }
    }
    
    int pipefd[2];
    pid_t pid;
    
    // 创建管道
    if (pipe(pipefd) == -1) {
        DEBUG_PRINT("创建管道失败: %s\n", strerror(errno));
        return safe_strdup("错误：无法创建进程通信管道");
    }
    
    // 创建子进程
    pid = fork();
    if (pid == -1) {
        DEBUG_PRINT("创建子进程失败: %s\n", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        return safe_strdup("错误：无法创建处理进程");
    }
    
    if (pid == 0) {
        // 子进程
        close(pipefd[0]); // 关闭读端
        
        // 将标准输出重定向到管道写端
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO); // 重定向错误输出
        close(pipefd[1]);
        
        // 执行脚本
        execl("/bin/bash", "bash", PROCESS_SCRIPT, input_string, NULL);
        
        // 如果执行失败
        fprintf(stderr, "execl failed: %s\n", strerror(errno));
        exit(1);
    } else {
        // 父进程
        close(pipefd[1]); // 关闭写端
        
        char buffer[1024];
        ssize_t bytes_read;
        size_t total_size = 0;
        char* output = static_cast<char*>(malloc(4096));
        if (!output) {
            DEBUG_PRINT("内存分配失败\n");
            close(pipefd[0]);
            return safe_strdup("错误：内存分配失败");
        }
        output[0] = '\0';
        
        while ((bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytes_read] = '\0';
            
            // 检查是否需要更多空间
            if (total_size + bytes_read >= 4095) {
                DEBUG_PRINT("输出过长，截断\n");
                break;
            }
            
            strcat(output + total_size, buffer);
            total_size += bytes_read;
        }
        
        close(pipefd[0]);
        
        // 等待子进程结束
        int status;
        waitpid(pid, &status, 0);
        
        if (WIFEXITED(status)) {
            int exit_status = WEXITSTATUS(status);
            DEBUG_PRINT("脚本退出状态: %d\n", exit_status);
            
            if (exit_status != 0) {
                DEBUG_PRINT("脚本执行失败，退出状态: %d\n", exit_status);
                char* error_msg = static_cast<char*>(malloc(256));
                snprintf(error_msg, 256, "错误：脚本执行失败 (退出码: %d)", exit_status);
                free(output);
                return error_msg;
            }
        } else {
            DEBUG_PRINT("脚本异常终止\n");
            free(output);
            return safe_strdup("错误：脚本异常终止");
        }
        
        DEBUG_PRINT("脚本输出长度: %zu\n", strlen(output));
        return output;
    }
}

// 处理提交请求
void submit_handler(struct evhttp_request *req, void *arg) {
    DEBUG_PRINT("处理提交请求，URI: %s\n", evhttp_request_get_uri(req));
    
    // 添加 CORS 头
    struct evkeyvalq* headers = evhttp_request_get_output_headers(req);
    evhttp_add_header(headers, "Access-Control-Allow-Origin", "*");
    evhttp_add_header(headers, "Content-Type", "text/plain; charset=UTF-8");
    
    struct evbuffer *buf = evbuffer_new();
    if (!buf) {
        DEBUG_PRINT("创建缓冲区失败\n");
        evhttp_send_error(req, HTTP_INTERNAL, "Failed to create buffer");
        return;
    }
    
    // 检查请求方法
    enum evhttp_cmd_type method = evhttp_request_get_command(req);
    DEBUG_PRINT("请求方法: %d\n", method);
    
    if (method == EVHTTP_REQ_OPTIONS) {
        // 处理 OPTIONS 请求
        options_handler(req, arg);
        evbuffer_free(buf);
        return;
    }
    
    if (method != EVHTTP_REQ_POST) {
        DEBUG_PRINT("不支持的请求方法: %d\n", method);
        evbuffer_add_printf(buf, "错误：只支持 POST 方法");
        evhttp_send_reply(req, HTTP_BADMETHOD, "Method Not Allowed", buf);
        evbuffer_free(buf);
        return;
    }
    
    // 读取 POST 数据
    struct evbuffer *input_buf = evhttp_request_get_input_buffer(req);
    size_t len = evbuffer_get_length(input_buf);
    
    DEBUG_PRINT("接收到 %zu 字节的 POST 数据\n", len);
    
    if (len > 0) {
        char *post_data = static_cast<char*>(malloc(len + 1));
        if (!post_data) {
            DEBUG_PRINT("内存分配失败\n");
            evhttp_send_error(req, HTTP_INTERNAL, "Memory allocation failed");
            evbuffer_free(buf);
            return;
        }
        
        evbuffer_remove(input_buf, post_data, len);
        post_data[len] = '\0';
        
        DEBUG_PRINT("原始 POST 数据: %s\n", post_data);
        
        char *input_string = NULL;
        char *decoded_string = NULL;
        
        const char* content_type = get_content_type(req);
        
        if (content_type && strstr(content_type, "multipart/form-data") != NULL) {
            DEBUG_PRINT("处理 multipart/form-data - 暂不支持\n");
            evbuffer_add_printf(buf, "错误：暂不支持 multipart/form-data 格式");
        } else {
            DEBUG_PRINT("处理 application/x-www-form-urlencoded\n");
            // 简单的参数解析
            const char* key = "inputString=";
            char* param_start = strstr(post_data, key);
            if (param_start) {
                param_start += strlen(key);
                char* param_end = strchr(param_start, '&');
                if (param_end) {
                    *param_end = '\0';
                }
                input_string = param_start;
                decoded_string = url_decode(input_string);
            }
        }
        
        if (decoded_string && strlen(decoded_string) > 0) {
            DEBUG_PRINT("收到字符串: %s\n", decoded_string);
            printf("服务器日志: 收到字符串 - \"%s\"\n", decoded_string);
            spdlog::info("收到字符串: \"{}\"", decoded_string);
            // 调用脚本处理字符串
            char* script_output = call_process_script(decoded_string);
            printf("服务器日志: 脚本处理结果 - \"%s\"\n", script_output ? script_output : "无输出");
            spdlog::info("处理结果: \"{}\"", script_output ? script_output : "无输出");
            
            if (script_output) {
                evbuffer_add_printf(buf, "收到字符串: \"%s\"\n处理结果:\n%s", 
                                   decoded_string, script_output);
                free(script_output);
            } else {
                evbuffer_add_printf(buf, "收到字符串: \"%s\"\n（无输出）", decoded_string);
            }
            
            free(decoded_string);
        } else {
            DEBUG_PRINT("未接收到有效的字符串\n");
            spdlog::info("错误：未接收到有效的字符串。接收到的数据: \"{}\"", post_data);
            evbuffer_add_printf(buf, "错误：未接收到有效的字符串。接收到的数据: %s", post_data);
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
    const char* uri = evhttp_request_get_uri(req);
    DEBUG_PRINT("处理未找到的路径: %s\n", uri);
    
    // 添加 CORS 头
    struct evkeyvalq* headers = evhttp_request_get_output_headers(req);
    evhttp_add_header(headers, "Access-Control-Allow-Origin", "*");
    
    struct evbuffer *buf = evbuffer_new();
    if (!buf) {
        evhttp_send_error(req, HTTP_INTERNAL, "Failed to create buffer");
        return;
    }
    spdlog::info("404 - 页面未找到。请求的路径: {}", uri);
    evbuffer_add_printf(buf, "404 - 页面未找到。请求的路径: %s", uri);
    evhttp_send_reply(req, HTTP_NOTFOUND, "Not Found", buf);
    evbuffer_free(buf);
}

// 信号处理函数
void signal_handler(int sig) {
    DEBUG_PRINT("接收到信号 %d\n", sig);
    printf("接收到信号 %d，正在关闭服务器...\n", sig);
    exit(0);
}

bool initLog()
{
      // 确保日志目录存在
    std::string log_dir = "logs";
    if (!std::filesystem::exists(log_dir)) {
        std::filesystem::create_directories(log_dir);
    }

    try {
        // 1. 创建一个循环文件记录器
        // 参数：记录器名称, 文件路径, 单个文件最大大小(字节), 保留的旧文件数量
        auto max_size = 1024 * 1024 * 5; // 5MB
        auto max_files = 3;
        auto file_logger = spdlog::rotating_logger_mt("file_logger", "logs/uranus_auth_server.log", max_size, max_files);

        // 2. 设置为全局默认记录器（可选，这样可以直接使用 spdlog::info() 等函数）
        spdlog::set_default_logger(file_logger);

        // 3. 设置日志级别（只记录该级别及以上的日志）
        file_logger->set_level(spdlog::level::debug);
        // 或设置全局级别：spdlog::set_level(spdlog::level::info);

        // 4. 设置日志格式 [时间] [级别] [线程ID] 正文
        file_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [thread %t] %v");

        // // 5. 设置遇到指定级别及以上日志时立即刷新到文件，而非缓冲:cite[2]:cite[8]
        file_logger->flush_on(spdlog::level::info);

        // 开始记录日志
        spdlog::info("日志初始化成功！");

        // 程序结束时，spdlog 会自动刷新并关闭日志文件。
        // 但显式关闭是一个好习惯，尤其是在长期运行的程序中:cite[9]。
        return true;
    }
    catch (const spdlog::spdlog_ex& ex) {
        // 处理创建记录器时可能发生的异常（如权限问题、路径无效等）
        printf("日志初始化失败: %s\n", ex.what());
        return false;
    }
    return false;
}

int main(int argc, char *argv[]) {
    DEBUG_PRINT("启动 HTTP 服务器\n");

    bool bInitlog = initLog();

    
    struct event_base *base;
    struct evhttp *http;
    struct evhttp_bound_socket *handle;
    
    unsigned short port = 8080;
    
    int iReturn = 1;
    do
    {
        // 解析命令行参数
        if (argc > 1) {
            port = atoi(argv[1]);
            if (port == 0) {
                fprintf(stderr, "无效的端口号: %s\n", argv[1]);
                break;
            }
        }
        
        DEBUG_PRINT("使用端口: %d\n", port);
        
        // 检查脚本
        if (access(PROCESS_SCRIPT, X_OK) != 0) {
            spdlog::info("提示: 处理脚本 {} 不存在，将在首次使用时创建默认脚本", PROCESS_SCRIPT);
        } else {
            spdlog::info("提示: 处理脚本 {} 存在", PROCESS_SCRIPT);
        }
        
        // 创建 event base
        base = event_base_new();
        if (!base) {
            fprintf(stderr, "创建 event base 失败\n");
            break;
        }
        
        DEBUG_PRINT("event base 创建成功\n");
        
        // 创建 HTTP 服务器
        http = evhttp_new(base);
        if (!http) {
            fprintf(stderr, "创建 HTTP 服务器失败\n");
            break;
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
            fprintf(stderr, "绑定到端口 %d 失败: %s\n", port, strerror(errno));
            break;
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
        iReturn = 0;
    } while(0);


    if(bInitlog)
    {
        spdlog::shutdown();
    }
    return iReturn;
}
package com.security.analysis;

import com.code_intelligence.jazzer.api.BugDetectors;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 通过发起真实连接来对 MySQL JDBC URL 进行 Fuzz 测试。
 * 此版本依赖于外部的 Method Hook (例如 MysqlFileReadHook) 来检测深层次的安全问题。
 */
public class VerboseMySQLJdbcUrlFuzzer {

//    private static final AtomicLong TOTAL_EXECUTIONS = new AtomicLong(0);
//    private static final long OUTPUT_EVERY_N = 1000; // 每1000次输出一次进度

    private static final boolean OUTPUT_ALL = Boolean.parseBoolean(System.getProperty("fuzzer.output.all", "false"));
    private static final boolean STATS_ONLY = Boolean.parseBoolean(System.getProperty("fuzzer.stats.only", "false"));
    private static final long OUTPUT_EVERY_N = Long.parseLong(System.getProperty("fuzzer.output.every", "1000"));

    private static final AtomicLong TOTAL_EXECUTIONS = new AtomicLong(0);
    private static final AtomicLong SUCCESSFUL_CONNECTIONS = new AtomicLong(0);
    private static final AtomicLong FAILED_CONNECTIONS = new AtomicLong(0);
    private static final AtomicLong OTHER_EXCEPTIONS = new AtomicLong(0);

    // 定义变异策略，这部分对于生成多样化的输入至关重要
    public enum MutationStrategy {
        STANDARD("Standard"),
        SPACE_INJECTION("Space Injection"),
        TAB_INJECTION("Tab Injection"),
        CASE_VARIATION("Case Variation"),
        URL_ENCODING("URL Encoding"),
        DOUBLE_ENCODING("Double Encoding"),
        UNICODE_ENCODING("Unicode Encoding"),
        COMMENT_INJECTION("Comment Injection"),
        PARAMETER_POLLUTION("Parameter Pollution"),
        MIXED_ENCODING("Mixed Encoding");

        private final String description;

        MutationStrategy(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }

    // 静态初始化块，只执行一次
    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            System.out.println("[INIT] MySQL Driver loaded successfully");
        } catch (ClassNotFoundException e) {
            System.err.println("[ERROR] Failed to load MySQL driver: " + e);
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {

        // 授权对本地回环地址(localhost)的网络连接，以禁用Jazzer的SSRF检测。
        // 这是预期的行为，因为我们需要真实连接到本地数据库。
        try {
            BugDetectors.allowNetworkConnections((host, port) -> {
                try {
                    InetAddress addr = InetAddress.getByName(host);
                    return addr.isLoopbackAddress(); // 只允许连接到 localhost
                } catch (UnknownHostException e) {
                    return false;
                }
            });
        } catch (Throwable e) {
            // 忽略设置检测器时可能出现的异常
        }

        long executionCount = TOTAL_EXECUTIONS.incrementAndGet();

        // 1. 使用多种策略生成一个可能有害的 JDBC URL
        MutationStrategy strategy = data.pickValue(MutationStrategy.values());
        String jdbcUrl = generateMutatedUrl(data, strategy) + "&useSSL=false";

        if (!STATS_ONLY && (OUTPUT_ALL || executionCount % OUTPUT_EVERY_N == 0)) {
            System.out.printf("[INFO #%d] URL: %s\n", executionCount, jdbcUrl);
        }

        Connection conn = null;
        try {
            // 2. 核心改动：尝试使用生成的URL发起真实连接
            // 这将触发JDBC驱动的完整解析逻辑。
            // 如果我们的Hook (MysqlFileReadHook) 检测到恶意行为 (如读取/etc/passwd),
            // 它会抛出RuntimeException, Jazzer会捕获并报告为安全问题。
            conn = DriverManager.getConnection(jdbcUrl, "user", "password");
            System.out.println("[SUCCESS] Connection established!");
        } catch (SQLException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException && cause.getMessage() != null &&
                    cause.getMessage().startsWith("Fuzzing successful")) {
                // 如果异常的根本原因是我们的Hook抛出的，就重新把它抛出来给Jazzer看！
                // 发现漏洞，将其写入文件并重新抛出
                logFinding(jdbcUrl, cause);
                throw (RuntimeException) cause;
            }

            // 否则，这只是一个普通的SQL连接失败，可以忽略
            // System.err.println("Suppressed SQLException: " + e.getMessage());
            if (executionCount % 5000 == 0) { // 降低输出频率
                System.err.println("[SQL ERROR] " + e.getMessage() + " for URL: " + jdbcUrl);
            }
        } catch (RuntimeException e) {
            System.out.println("fuzzerTestOneInput: " + e.getMessage());
        } catch (Exception e) {
            // 捕获其他非预期的异常，可以选择打印出来进行调试
            System.err.printf("Unexpected exception for URL [%s]: %s\n", jdbcUrl, e.getMessage());
//            System.err.println("[ERROR] Unexpected: " + e.getMessage());
        } finally {
            // 3. 确保任何成功建立的连接都被关闭，防止资源泄露
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    // 忽略关闭时的异常
                }
            }
        }
    }

    /**
     * 生成经过变异的URL (保留原逻辑)
     */
    public static String generateMutatedUrl(FuzzedDataProvider data, MutationStrategy strategy) {
        StringBuilder url = new StringBuilder("jdbc:mysql://");

        // Host部分
        url.append(data.pickValue(new String[]{"localhost", "127.0.0.1"}));
        url.append(":").append(3306);
        url.append("/").append(data.pickValue(new String[]{"test", "mysql", ""}));
        url.append("?");

        // 构建参数列表
        List<String> params = new ArrayList<>();

        // 添加一个主要的危险参数，这是触发漏洞的关键
        String mainParamKey = data.pickValue(new String[]{
                "allowLoadLocalInfile",
                "allowUrlInLocalInfile",
        });
        String mainParamValue = data.pickValue(new String[]{"true", "TRUE", "1", "yes"});
        params.add(applyMutation(mainParamKey, mainParamValue, strategy, data));

        // 组合参数
        url.append(String.join("&", params));

        return url.toString();
    }

    /**
     * 对参数的键值对应用变异策略 (保留原逻辑)
     */
    private static String applyMutation(String key, String value,
                                        MutationStrategy strategy,
                                        FuzzedDataProvider data) {
        String result;
        switch (strategy) {
            case SPACE_INJECTION:
                result = key + " = " + value;
                break;
            case TAB_INJECTION:
                result = key + "\t=\t" + value;
                break;
            case CASE_VARIATION:
                result = varyCase(key, data) + "=" + varyCase(value, data);
                break;
            case URL_ENCODING:
                result = urlEncode(key) + "=" + urlEncode(value);
                break;
            case DOUBLE_ENCODING:
                result = urlEncode(urlEncode(key)) + "=" + urlEncode(urlEncode(value));
                break;
            case UNICODE_ENCODING:
                result = unicodeEncode(key, data) + "=" + value;
                break;
            case COMMENT_INJECTION:
                result = key + "/*comment*/=" + value;
                break;
            case PARAMETER_POLLUTION:
                // 模拟参数污染，尝试用一个后面的"true"覆盖前面的"false"
                return key + "=false&dummy=1&" + key + "=" + value;
            case MIXED_ENCODING:
                String mixedKey = "";
                for (char c : key.toCharArray()) {
                    mixedKey += data.consumeBoolean() ? "%" + String.format("%02X", (int) c) : c;
                }
                result = mixedKey + "=" + value;
                break;
            default: // STANDARD
                result = key + "=" + value;
        }
        return result;
    }

    // 辅助的变异方法 (保留)
    private static String varyCase(String str, FuzzedDataProvider data) {
        StringBuilder sb = new StringBuilder();
        for (char c : str.toCharArray()) {
            sb.append(data.consumeBoolean() ? Character.toUpperCase(c) : Character.toLowerCase(c));
        }
        return sb.toString();
    }

    private static String urlEncode(String str) {
        try {
            return java.net.URLEncoder.encode(str, "UTF-8");
        } catch (Exception e) {
            return str;
        }
    }


    private static String unicodeEncode(String str, FuzzedDataProvider data) {
        // 不要使用Unicode转义序列，因为它们在URL中不会被自动解析
        // 改用URL编码或其他编码方式
        StringBuilder sb = new StringBuilder();
        for (char c : str.toCharArray()) {
            if (data.consumeBoolean() && Character.isLetter(c)) {
                // 使用URL编码而不是Unicode转义
                sb.append("%").append(String.format("%02X", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    // --- 新增：将发现写入文件的辅助方法 ---
    private static void logFinding(String url, Throwable cause) {
        String timestamp = new SimpleDateFormat("yyyyMMdd-HHmmss-SSS").format(new Date());
        String fileName = "findings/security-issue-" + timestamp + ".txt";
        try (PrintWriter writer = new PrintWriter(new FileWriter(fileName))) {
            writer.println("!!! SECURITY FINDING DETECTED !!!");
            writer.println("====================================");
            writer.println("Timestamp: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
            writer.println("Triggering URL: " + url);
            writer.println("------------------------------------");
            writer.println("Stack Trace:");
            cause.printStackTrace(writer);
            System.out.println("\n[SECURITY] Finding logged to: " + fileName);
        } catch (IOException e) {
            System.err.println("Failed to write finding to file: " + e.getMessage());
        }
    }
}
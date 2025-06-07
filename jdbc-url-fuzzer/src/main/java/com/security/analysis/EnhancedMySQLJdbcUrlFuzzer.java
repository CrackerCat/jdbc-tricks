package com.security.analysis;

import com.code_intelligence.jazzer.api.BugDetectors;
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.security.analysis.harness.HarnessFilter;
import com.security.analysis.harness.HarnessFilterManager;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 增强版MySQL JDBC URL Fuzzer
 * 支持动态加载和测试多个CVE过滤器，并引入了从文件加载种子的功能
 */
public class EnhancedMySQLJdbcUrlFuzzer {

    private static final boolean OUTPUT_ALL = Boolean.parseBoolean(System.getProperty("fuzzer.output.all", "false"));
    private static final boolean STATS_ONLY = Boolean.parseBoolean(System.getProperty("fuzzer.stats.only", "false"));
    private static final long OUTPUT_EVERY_N = Long.parseLong(System.getProperty("fuzzer.output.every", "1000"));

    private static final AtomicLong TOTAL_EXECUTIONS = new AtomicLong(0);
    private static final Map<String, AtomicLong> CVE_TEST_COUNTS = new HashMap<>();
    private static final Map<String, AtomicLong> CVE_BYPASS_COUNTS = new HashMap<>();

    // 获取CVE过滤器管理器实例
    private static final HarnessFilterManager filterManager = HarnessFilterManager.getInstance();

    // **改动**: 从硬编码数组改为动态列表，用于存储从文件读取的种子
    private static final List<String> SEED_URLS = new ArrayList<>();

    // 定义通用的危险参数池，用于测试各种CVE
    private static final String[] DANGEROUS_PARAMETERS = {
            // 文件读取相关
            "allowLoadLocalInfile", "allowUrlInLocalInfile", "allowLoadLocalInfileInPath",
//            // 反序列化相关
//            "autoDeserialize", "queryInterceptors", "statementInterceptors",
//            // 其他潜在危险参数
//            "maxAllowedPacket", "detectCustomCollations", "useServerPrepStmts",
//            "cachePrepStmts", "prepStmtCacheSqlLimit", "useOldAliasMetadataBehavior",
//            "useCompression", "paranoid", "processEscapeCodesForPrepStmts",
//            "useInformationSchema", "pedantic", "useUnicode", "characterEncoding",
//            "characterSetResults", "connectionCollation", "sessionVariables",
//            // 变体和大小写混合
//            "ALLOWLOADLOCALINFILE", "AllowLoadLocalInFile", "aLlOwLoAdLoCaLiNfIlE",
//            "allow_load_local_infile", "allowloadlocalinfile", "AllowUrlInLocalInfile"
    };

    // 定义变异策略
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
        MIXED_ENCODING("Mixed Encoding"),
        NULL_BYTE_INJECTION("Null Byte Injection"),
        NEWLINE_INJECTION("Newline Injection"),
        BACKSLASH_INJECTION("Backslash Injection");

        private final String description;

        MutationStrategy(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }

    // 静态初始化块
    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            System.out.println("[INIT] MySQL Driver loaded successfully");

            // 从文件加载种子
            loadSeedsFromFile("seeds/seeds.txt");

            // 初始化每个CVE的计数器
            for (HarnessFilter filter : filterManager.getFilters()) {
                CVE_TEST_COUNTS.put(filter.getHarnessNumber(), new AtomicLong(0));
                CVE_BYPASS_COUNTS.put(filter.getHarnessNumber(), new AtomicLong(0));
            }

            System.out.println("[INIT] Initialized counters for " + filterManager.getFilters().size() + " CVE filters");

        } catch (ClassNotFoundException e) {
            System.err.println("[ERROR] Failed to load MySQL driver: " + e);
        }
    }

    /**
     * **新增**: 从指定文件加载种子URL
     * @param fileName 包含种子URL的文件名
     */
    private static void loadSeedsFromFile(String fileName) {
        try {
            // 从文件中读取所有行
            List<String> lines = Files.readAllLines(Paths.get(fileName));
            for (String line : lines) {
                // 忽略空行和注释行 (以#开头)
                if (line != null && !line.trim().isEmpty() && !line.trim().startsWith("#")) {
                    SEED_URLS.add(line.trim());
                }
            }
            System.out.println("[INIT] Loaded " + SEED_URLS.size() + " seeds from " + fileName);
        } catch (IOException e) {
            // 如果文件不存在或读取失败，打印警告并继续
            System.err.println("[INIT] Warning: Could not read seeds file '" + fileName + "'. Proceeding without seeds. Reason: " + e.getMessage());
        }
    }

    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        // 设置允许本地连接
        setupBugDetectors();

        long executionCount = TOTAL_EXECUTIONS.incrementAndGet();

        // 选择要测试的CVE过滤器
        List<HarnessFilter> filters = filterManager.getFilters();
        if (filters.isEmpty()) {
            System.err.println("[ERROR] No CVE filters found!");
            return;
        }

        // 随机选择一个CVE过滤器进行测试
        HarnessFilter targetFilter = data.pickValue(filters);
        CVE_TEST_COUNTS.get(targetFilter.getHarnessNumber()).incrementAndGet();

        // 随机决定是使用种子还是从头生成URL
        String baseUrl;
        // 检查种子列表是否为空
        boolean useSeed = data.consumeBoolean() && !SEED_URLS.isEmpty();
        if (useSeed) {
            // 模式一：基于种子进行变异
            baseUrl = data.pickValue(SEED_URLS);
        } else {
            // 模式二：从头生成URL
            baseUrl = generateBaseUrlFromScratch(data);
        }

        // 基于选定的基础URL，应用变异策略生成最终的URL
        MutationStrategy strategy = data.pickValue(MutationStrategy.values());
        String jdbcUrl = applyMutationsToBaseUrl(data, baseUrl, strategy);

        if (!STATS_ONLY && (OUTPUT_ALL || executionCount % OUTPUT_EVERY_N == 0)) {
            System.out.printf("[INFO #%d] Testing %s with strategy %s (Mode: %s)\n",
                    executionCount, targetFilter.getHarnessNumber(), strategy.getDescription(), useSeed ? "Seed" : "Generate");
            System.out.printf("[INFO #%d] Base URL: %s\n", executionCount, baseUrl);
            System.out.printf("[INFO #%d] Final URL: %s\n", executionCount, jdbcUrl);
        }

        // 测试过滤器
        testFilterWithConnection(jdbcUrl, targetFilter, executionCount);

        // 定期输出统计信息
        if (executionCount % 10000 == 0) {
            printStatistics();
        }
    }

    /**
     * 从零开始生成一个基础JDBC URL
     */
    private static String generateBaseUrlFromScratch(FuzzedDataProvider data) {
        StringBuilder url = new StringBuilder("jdbc:mysql://");
        url.append(data.pickValue(new String[]{"localhost", "127.0.0.1", "::1"}));
        url.append(":").append(data.pickValue(new Integer[]{3306, 3307, 3308}));
        url.append("/").append(data.pickValue(new String[]{"test", "mysql", "db", ""}));
        return url.toString();
    }

    /**
     * 在给定的基础URL上应用变异策略
     * 这个方法会向URL添加带有各种变异的危险参数
     */
    private static String applyMutationsToBaseUrl(FuzzedDataProvider data,
                                                  String baseUrl,
                                                  MutationStrategy strategy) {
        StringBuilder url = new StringBuilder(baseUrl);

        // 检查基础URL是否已有参数
        if (baseUrl.contains("?")) {
            // 如果URL以 '?' 结尾，不添加任何东西。否则添加 '&'
            if (!baseUrl.endsWith("?") && !baseUrl.endsWith("&")) {
                url.append("&");
            }
        } else {
            url.append("?");
        }

        // 构建一个包含变异后危险参数的列表
        List<String> params = new ArrayList<>();
        int numDangerousParams = data.consumeInt(1, 3);
        for (int i = 0; i < numDangerousParams; i++) {
            String dangerousParam = data.pickValue(DANGEROUS_PARAMETERS);
            String value = data.pickValue(new String[]{
                    "true", "TRUE", "1", "yes", "YES"
            });
            params.add(applyMutation(dangerousParam, value, strategy, data));
        }

        // 将新的参数附加到URL上
        url.append(String.join("&", params));

        return url.toString();
    }

    /**
     * 测试过滤器并尝试建立连接
     */
    private static void testFilterWithConnection(String jdbcUrl, HarnessFilter filter, long executionCount) {
        Connection conn = null;

        try {
            // 首先通过过滤器
            String filteredUrl = filter.filterSensitive(jdbcUrl);

            // 如果过滤器没有抛出异常，说明URL通过了过滤
            // 现在尝试建立连接看是否会触发Hook
            try {
                conn = DriverManager.getConnection(filteredUrl + "&useSSL=false", "user", "password");

                // 如果连接成功且没有触发Hook，这本身不算绕过，因为Hook只关心特定行为（如读文件）
                if (!STATS_ONLY && OUTPUT_ALL) {
                    System.out.printf("[FILTER PASSED] %s filter passed URL: %s\n",
                            filter.getHarnessNumber(), jdbcUrl);
                }

            } catch (SQLException e) {
                // 检查是否是Hook触发的异常
                Throwable cause = e.getCause();
                if (cause instanceof RuntimeException && cause.getMessage() != null &&
                        cause.getMessage().startsWith("Fuzzing successful")) {
                    // 过滤器被绕过了！
                    CVE_BYPASS_COUNTS.get(filter.getHarnessNumber()).incrementAndGet();
                    logBypass(jdbcUrl, filter, cause);
                    throw (RuntimeException) cause;
                }
                // 普通的SQL异常，忽略
            }

        } catch (Exception filterException) {
            // 过滤器正确地拒绝了危险URL
            if (!STATS_ONLY && executionCount % 5000 == 0) {
                System.out.printf("[FILTER BLOCKED] %s blocked URL with: %s\n",
                        filter.getHarnessNumber(), filterException.getMessage());
            }
        } finally {
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    // 忽略关闭异常
                }
            }
        }
    }

    /**
     * 对参数应用变异策略
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
                return key + "=false&dummy=1&" + key + "=" + value;
            case NULL_BYTE_INJECTION:
                result = key + "\0=" + value;
                break;
            case NEWLINE_INJECTION:
                result = key + "\n=" + value;
                break;
            case BACKSLASH_INJECTION:
                result = key.replace("a", "\\a") + "=" + value;
                break;
            case MIXED_ENCODING:
                StringBuilder mixedKey = new StringBuilder();
                for (char c : key.toCharArray()) {
                    mixedKey.append(data.consumeBoolean() ? "%" + String.format("%02X", (int) c) : c);
                }
                result = mixedKey.toString() + "=" + value;
                break;
            default: // STANDARD
                result = key + "=" + value;
        }
        return result;
    }

    // 辅助方法
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
        StringBuilder sb = new StringBuilder();
        for (char c : str.toCharArray()) {
            if (data.consumeBoolean() && Character.isLetter(c)) {
                sb.append("%").append(String.format("%02X", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static void setupBugDetectors() {
        try {
            BugDetectors.allowNetworkConnections((host, port) -> {
                try {
                    InetAddress addr = InetAddress.getByName(host);
                    return addr.isLoopbackAddress();
                } catch (UnknownHostException e) {
                    return false;
                }
            });
        } catch (Throwable e) {
            // 忽略
        }
    }

    /**
     * 记录过滤器绕过
     */
    private static void logBypass(String url, HarnessFilter filter, Throwable cause) {
        String timestamp = new SimpleDateFormat("yyyyMMdd-HHmmss-SSS").format(new Date());
        String fileName = String.format("findings/%s-bypass-%s.txt", filter.getHarnessNumber(), timestamp);

        try (PrintWriter writer = new PrintWriter(new FileWriter(fileName, true))) {
            writer.println("!!! FILTER BYPASS DETECTED !!!");
            writer.println("====================================");
            writer.println("CVE Number: " + filter.getHarnessNumber());
            writer.println("CVE Description: " + filter.getDescription());
            writer.println("Timestamp: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
            writer.println("Bypassing URL: " + url);
            writer.println("------------------------------------");
            writer.println("Stack Trace:");
            cause.printStackTrace(writer);
            writer.println("\n");

            System.out.println("\n[SECURITY] Filter bypass logged to: " + fileName);

        } catch (IOException e) {
            System.err.println("Failed to write bypass to file: " + e.getMessage());
        }
    }

    /**
     * 打印统计信息
     */
    private static void printStatistics() {
        System.out.println("\n======== FUZZING STATISTICS ========");
        System.out.println("Total Executions: " + TOTAL_EXECUTIONS.get());
        System.out.println("\nPer-CVE Statistics:");

        for (HarnessFilter filter : filterManager.getFilters()) {
            String cve = filter.getHarnessNumber();
            long tests = CVE_TEST_COUNTS.getOrDefault(cve, new AtomicLong(0)).get();
            long bypasses = CVE_BYPASS_COUNTS.getOrDefault(cve, new AtomicLong(0)).get();

            System.out.printf("  %s: %d tests, %d bypasses (%.2f%%)\n",
                    cve, tests, bypasses,
                    tests > 0 ? (bypasses * 100.0 / tests) : 0);
        }
        System.out.println("===================================\n");
    }
}

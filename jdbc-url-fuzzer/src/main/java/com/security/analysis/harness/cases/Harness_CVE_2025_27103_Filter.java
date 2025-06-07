package com.security.analysis.harness.cases;

import com.security.analysis.harness.HarnessFilter;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Harness_CVE_2025_27103_Filter implements HarnessFilter {

    private static final Pattern JDBC_URL_PATTERN = Pattern.compile(
            "^jdbc:mysql://([a-zA-Z0-9.-]+)(:(\\d+))?/([a-zA-Z0-9_.-]+)(\\?(.*))?$"
    );

    private String driver = "com.mysql.cj.jdbc.Driver";
    private String extraParams = "characterEncoding=UTF-8 & connectTimeout = 5000 & useSSL = false & allowPublicKeyRetrieval = true & zeroDateTimeBehavior = convertToNull ";
    private static List<String> illegalParameters =
            Arrays.asList("maxAllowedPacket", "autoDeserialize", "queryInterceptors",
                    "statementInterceptors", "detectCustomCollations", "allowloadlocalinfile", "allowUrlInLocalInfile", "allowLoadLocalInfileInPath");
    private List<String> showTableSqls = Arrays.asList("show tables");

    @Override
    public String getHarnessNumber() {
        return "CVE-2025-27103";
    }

    @Override
    public String getDescription() {
        return "https://github.com/dataease/dataease/security/advisories/GHSA-v4gg-8rp3-ccjx";
    }

    @Override
    public String filterSensitive(String originalUrl) throws Exception {
        if (isBlank(originalUrl)) {
            throw new Exception("Input URL cannot be empty.");
        }

        // 1. 解析URL
        Matcher matcher = JDBC_URL_PATTERN.matcher(originalUrl);
        if (!matcher.matches()) {
            throw new Exception("Invalid JDBC URL format. Expected: jdbc:mysql://host:port/database?params");
        }

        // 从正则表达式的捕获组中提取信息
        String host = matcher.group(1);
        // 如果端口不存在，则使用MySQL默认端口3306
        String portStr = matcher.group(3);
        int port = (portStr != null) ? Integer.parseInt(portStr) : 3306;
        String database = matcher.group(4);
        // 查询参数可能不存在
        String queryParams = matcher.group(6);


        // 2. 校验提取出的查询参数
        if (!isBlank(queryParams)) {
            try {
                String decodedParams = URLDecoder.decode(queryParams, StandardCharsets.UTF_8.name()).toLowerCase();
                for (String illegalParam : illegalParameters) {
                    // 精确匹配 "参数名="
                    if (decodedParams.contains(illegalParam.toLowerCase() + "=")) {
                        throw new Exception("Illegal parameter detected in URL: " + illegalParam);
                    }
                }
            } catch (UnsupportedEncodingException e) {
                throw new Exception("Failed to decode URL parameters", e);
            }
        }

        // 3. 重构URL
        // 使用解析出的、经过验证的组件来重新构建URL，确保安全。
        StringBuilder safeUrlBuilder = new StringBuilder();
        safeUrlBuilder.append("jdbc:mysql://")
                .append(host)
                .append(":")
                .append(port)
                .append("/")
                .append(database);

        if (!isBlank(queryParams)) {
            safeUrlBuilder.append("?").append(queryParams);
        }

        return safeUrlBuilder.toString();
    }

    private static boolean isBlank(String str) {
        return str == null || str.trim().isEmpty();
    }
}

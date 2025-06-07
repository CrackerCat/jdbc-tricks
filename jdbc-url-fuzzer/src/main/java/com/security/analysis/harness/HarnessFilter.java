package com.security.analysis.harness;

/**
 * Harness过滤器接口
 * 所有Harness相关的过滤器都应该实现此接口
 */
public interface HarnessFilter {

    /**
     * 获取Harness编号
     * @return Harness编号，例如 "CVE-2025-27103"
     */
    String getHarnessNumber();

    /**
     * 获取Harness描述
     * @return Harness的简要描述
     */
    String getDescription();

    /**
     * 过滤敏感参数
     * 所有的过滤逻辑都应该在此方法中实现
     * @param originalUrl 原始的JDBC URL
     * @return 过滤后的安全URL
     * @throws Exception 如果URL格式不正确或包含非法参数
     */
    String filterSensitive(String originalUrl) throws Exception;
}

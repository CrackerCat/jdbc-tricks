package com.jdbc.tricks.quote_bypass;

import com.jdbc.tricks.utils.MysqlConnectionUtils;

/**
 * 驱动解析提取引号内的内容
 * 驱动版本：mysql-connector-java 5.1.16
 */
public class QuoteBypass {
    public static void main(String[] args) {
        String url = "jdbc:mysql://(127.0.0.1,allowLoadLocal='true')/test";
        MysqlConnectionUtils.connect(url, "root", "root",false);
    }
}

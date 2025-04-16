package com.jdbc.tricks.default_properties;

import com.jdbc.tricks.utils.MysqlConnectionUtils;

/**
 * 驱动默认配置allowLoadLocalInfile=true，无需任何配置即可触发任意文件读取漏洞
 * 驱动版本：mysql-connector-java 8.0.12
 */
public class DefaultProperties {

    public static void main(String[] args) {
        String url = "jdbc:mysql://127.0.0.1:3306/test?allowLoadLocal=True";
        MysqlConnectionUtils.connect(url, "root", "root");
    }
}

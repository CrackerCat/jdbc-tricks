package com.jdbc.tricks.default_properties;

import com.jdbc.tricks.utils.MysqlConnectionUtils;

/**
 * 驱动默认配置allowLoadLocalInfile=true，无需任何配置即可触发任意文件读取漏洞，详情查看：
 * jdbc-test-case/version5/src/main/java/com/jdbc/tricks/default_properties/README.md
 * 驱动版本：mysql-connector-java 5.1.16
 */
public class DefaultProperties {

    public static void main(String[] args) {
        String url = "jdbc:mysql://127.0.0.1:3306/test";
        MysqlConnectionUtils.connect(url, "root", "root",false);
    }
}

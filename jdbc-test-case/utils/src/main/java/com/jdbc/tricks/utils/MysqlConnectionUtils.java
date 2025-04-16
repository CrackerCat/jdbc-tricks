package com.jdbc.tricks.utils;

import java.sql.DriverManager;

public class MysqlConnectionUtils {

    private static final String STAR_ROCKS_DRIVER_CLASS = "com.mysql.jdbc.Driver";

    public static void connect(String jdbcUrl, String user, String password) {
        try {
            Class.forName(STAR_ROCKS_DRIVER_CLASS);
            DriverManager.getConnection(jdbcUrl, "etc", "mysql_clear_password");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

package com.jdbc.tricks.utils;

import java.sql.DriverManager;

public class MysqlConnectionUtils {

    private static final String STAR_ROCKS_DRIVER_CLASS = "com.mysql.jdbc.Driver";
    private static final String STAR_ROCKS_DRIVER_CLASS_CJ = "com.mysql.cj.jdbc.Driver";

    public static void connect(String jdbcUrl, String user, String password,boolean ifCJ) {
        try {
            if (ifCJ){
                Class.forName(STAR_ROCKS_DRIVER_CLASS_CJ);
            }else {
                Class.forName(STAR_ROCKS_DRIVER_CLASS);
            }
            DriverManager.getConnection(jdbcUrl, "etc", "mysql_clear_password");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

package com.jdbc.tricks;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * 感谢<a href="https://github.com/yggo">...</a>对<a href="https://github.com/yulate/jdbc-tricks/issues/2">...</a>的贡献
 */
public class Case_8x {
    public static void main(String[] args) {
        String url = "jdbc:mysql://xxxxxx/test?autoDeserialize=yes&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&socketFactory=com.mysql.cj.protocol.NamedPipeSocketFactory&namedPipePath={namedPipePath}";
        String username = "root";
        String password = "root";
        try (Connection connection = DriverManager.getConnection(url, username, password)) {
            System.out.println("数据库连接成功!");
        } catch (SQLException e) {
            System.out.println("数据库连接失败!");
            e.printStackTrace();
        }
    }
}

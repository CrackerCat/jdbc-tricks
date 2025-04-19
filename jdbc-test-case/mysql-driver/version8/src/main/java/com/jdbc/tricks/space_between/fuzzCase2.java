package com.jdbc.tricks.space_between;

import static com.mysql.cj.util.StringUtils.isNullOrEmpty;

/**
 * 空白字符fuzz
 */
public class fuzzCase2 {
    public static void main(String[] args) {
        // 注意：这里的循环范围超过了 char 的有效范围（0 ~ 65535），所以 i 大于 65535 时转换会发生截断。
        for (int i = 0; i <= 100000; i++) {
            char c = (char) i;
            String s = String.valueOf(c).replaceAll("\\s", "");
            if (!s.isEmpty()) {
                String s1 = safeTrim(s);
                if (isNullOrEmpty(s1)) {
                    // 使用 getEscapeSequence 输出转义序列
                    System.out.println(getEscapeSequence(c));
                }
            }
        }
    }

    /**
     * 如果字符串为 null 或空，返回原字符串，否则返回 trim 后的结果。
     */
    public static String safeTrim(String toTrim) {
        return isNullOrEmpty(toTrim) ? toTrim : toTrim.trim();
    }


    /**
     * 根据字符返回转义序列形式的字符串：
     * 对于 Java 中已有简写的控制字符，如 \b、\t、\n、\f、\r、\0 直接返回对应的转义字符串，
     * 其他则返回 Unicode 十六进制格式的表示，如 "\XXXX"。
     */
    public static String getEscapeSequence(char ch) {
        switch (ch) {
            case '\0':
                return "\\0";
            case '\b':
                return "\\b";
            case '\t':
                return "\\t";
            case '\n':
                return "\\n";
            case '\f':
                return "\\f";
            case '\r':
                return "\\r";
            default:
                return String.format("\\u%04X", (int) ch);
        }
    }
}

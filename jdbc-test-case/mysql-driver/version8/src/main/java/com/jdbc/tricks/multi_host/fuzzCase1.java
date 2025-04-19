package com.jdbc.tricks.multi_host;

/**
 * equalsIgnoreCase bypass key fuzz case
 */
public class fuzzCase1 {
    public static void main(String[] args) {
        String key = "abcdefghijklmnopqrstuvwxyz";
        for (int j = 0; j < key.length(); j++) {
            for (int i = 127; i <= 100000; i++) {
                if (String.valueOf((char) i).equalsIgnoreCase(String.valueOf(key.charAt(j)))) {
                    System.out.println(i);
                    System.out.println(key.charAt(j) + ": " + (char) i);
                }
            }
        }
    }
}

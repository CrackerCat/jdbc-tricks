package com.security.analysis.harness;

import com.security.analysis.harness.cases.Harness_CVE_2025_27103_Filter;

import java.io.File;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * Harness过滤器管理器
 * 负责动态加载和管理所有Harness过滤器
 */
public class HarnessFilterManager {

    private static final HarnessFilterManager INSTANCE = new HarnessFilterManager();
    private final List<HarnessFilter> filters = new ArrayList<>();

    private HarnessFilterManager() {
        loadFilters();
    }

    public static HarnessFilterManager getInstance() {
        return INSTANCE;
    }

    /**
     * 获取所有已加载的Harness过滤器
     */
    public List<HarnessFilter> getFilters() {
        return new ArrayList<>(filters);
    }

    /**
     * 根据Harness编号获取特定的过滤器
     */
    public HarnessFilter getFilter(String filterName) {
        return filters.stream()
                .filter(f -> f.getHarnessNumber().equals(filterName))
                .findFirst()
                .orElse(null);
    }

    /**
     * 动态加载包中的所有过滤器
     */
    private void loadFilters() {
        try {
            // 修正：使用正确的包路径
            String packageName = "com.security.analysis.harness.cases";
            String packagePath = packageName.replace('.', '/');
            ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            URL packageURL = classLoader.getResource(packagePath);

            if (packageURL != null) {
                File packageDir = new File(packageURL.toURI());
                if (packageDir.exists() && packageDir.isDirectory()) {
                    File[] files = packageDir.listFiles((dir, name) ->
                            name.endsWith(".class") &&
                                    name.startsWith("Harness_") &&
                                    name.contains("_Filter.class")
                    );

                    if (files != null) {
                        for (File file : files) {
                            String className = file.getName().replace(".class", "");
                            try {
                                Class<?> clazz = Class.forName(packageName + "." + className);
                                if (HarnessFilter.class.isAssignableFrom(clazz)) {
                                    HarnessFilter filter = (HarnessFilter) clazz.getDeclaredConstructor().newInstance();
                                    filters.add(filter);
                                    System.out.println("[HarnessFilterManager] Loaded filter: " + filter.getHarnessNumber());
                                }
                            } catch (Exception e) {
                                System.err.println("[HarnessFilterManager] Failed to load filter: " + className);
                                e.printStackTrace();
                            }
                        }
                    }
                }
            }

            // 如果通过文件系统加载失败，尝试手动注册已知的过滤器
            if (filters.isEmpty()) {
                registerKnownFilters();
            }

            System.out.println("[HarnessFilterManager] Total filters loaded: " + filters.size());

        } catch (Exception e) {
            System.err.println("[HarnessFilterManager] Error loading filters: " + e.getMessage());
            // 回退到手动注册
            registerKnownFilters();
        }
    }

    /**
     * 手动注册已知的过滤器（作为后备方案）
     */
    private void registerKnownFilters() {
        try {
            // 修正：添加实际的过滤器实例而不是null
            filters.add(new Harness_CVE_2025_27103_Filter());
            // 在这里添加更多的Harness过滤器
            // filters.add(new Harness_CVE_2024_XXXXX_Filter());
        } catch (Exception e) {
            System.err.println("[HarnessFilterManager] Failed to register known filters: " + e.getMessage());
        }
    }

    /**
     * 手动添加一个过滤器
     */
    public void addFilter(HarnessFilter filter) {
        if (filter != null && !filters.contains(filter)) {
            filters.add(filter);
            System.out.println("[HarnessFilterManager] Added filter: " + filter.getHarnessNumber());
        }
    }
}
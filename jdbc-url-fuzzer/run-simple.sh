#!/bin/bash

# --- 配置 ---
# 定义所有依赖项的路径，方便管理
JAZZER_LIB_DIR="lib"
MYSQL_CONNECTOR_JAR="${JAZZER_LIB_DIR}/mysql-connector-java-8.0.12.jar"
JAZZER_API_JAR="${JAZZER_LIB_DIR}/jazzer_standalone.jar" # 仅用于编译
FUZZER_SRC_DIR="src/main/java"
OUTPUT_DIR="out"

# --- 步骤 1: 编译 ---
# 更加健壮的编译步骤
echo "Compiling..."
# 清理旧的编译输出
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# 编译时，将 Jazzer API 和 MySQL 驱动都加入编译时类路径
javac -cp "${JAZZER_API_JAR}:${MYSQL_CONNECTOR_JAR}" -d "$OUTPUT_DIR" \
    "${FUZZER_SRC_DIR}/com/security/analysis/VerboseMySQLJdbcUrlFuzzer.java" \
    "${FUZZER_SRC_DIR}/com/security/analysis/MysqlFileReadHook.java"

# 检查编译是否成功
if [ $? -ne 0 ]; then
    echo "ERROR: Compilation failed. Aborting."
    exit 1
fi
echo "Compilation successful."


# --- 步骤 2: 运行 Fuzzer ---
# 不再创建 fat jar，而是使用 classpath
echo "Running Jazzer..."

# --cp 参数包含了:
# 1. 我们自己编译的类的输出目录 (out)
# 2. 原始、完整的 MySQL 驱动 JAR 包
# Jazzer 会自己处理好它自身的依赖，我们无需关心。
"${JAZZER_LIB_DIR}/jazzer" \
    --cp="${OUTPUT_DIR}:${MYSQL_CONNECTOR_JAR}" \
    --target_class="com.security.analysis.VerboseMySQLJdbcUrlFuzzer" \
    --custom_hooks="com.security.analysis.MysqlFileReadHook" \
    --jvm_args="--add-modules=java.sql" \
    --instrumentation_includes="com.security.analysis.**" \
    --instrumentation_includes="com.mysql.cj.**" \
    -max_len=4096 \
    -timeout=300 \
    --keep_going=10 \
    -print_final_stats=1 \
    -use_value_profile=1
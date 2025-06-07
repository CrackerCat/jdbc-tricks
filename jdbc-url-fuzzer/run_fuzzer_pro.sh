#!/bin/bash
# run_fuzzer_pro.sh - 专业的、带详细输出和成果管理的Fuzzer运行脚本

# --- 配置 ---
# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Fuzzer相关配置
TARGET_CLASS="com.security.analysis.VerboseMySQLJdbcUrlFuzzer"
TARGET_HOOK="com.security.analysis.MysqlFileReadHook"
# 修正: 明确指定MySQL驱动的JAR包路径，避免使用不可靠的通配符*
CLASSPATH="out:lib/mysql-connector-java-8.0.12.jar"

# 默认参数
VERBOSE_LEVEL="normal"  # normal, all, interesting
OUTPUT_FILE=""

# --- 解析命令行参数 ---
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose) VERBOSE_LEVEL="all"; shift ;;
        -i|--interesting) VERBOSE_LEVEL="interesting"; shift ;;
        -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  -v, --verbose      Show all generated URLs and properties"
            echo "  -i, --interesting  Show progress every 1000 iterations"
            echo "  -o, --output FILE  Save console output to file as well"
            echo "  -h, --help         Show this help"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# --- 准备工作 ---
# 创建必要的目录，用于存放编译产物、发现的漏洞和语料库
echo -e "${BLUE}[*] Creating directories: findings, corpus, logs, out...${NC}"
mkdir -p findings corpus logs out

# 设置输出重定向
if [ -n "$OUTPUT_FILE" ]; then
    # 将标准输出和标准错误都重定向到控制台和指定文件
    exec &> >(tee -a "$OUTPUT_FILE")
fi

# --- 打印启动信息 ---
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           MySQL JDBC URL Fuzzer - Professional Mode        ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo -e "${BLUE}[CONFIG] Verbose Level:${NC} ${YELLOW}$VERBOSE_LEVEL${NC}"
echo -e "${BLUE}[CONFIG] Log File:${NC}      ${YELLOW}${OUTPUT_FILE:-console}${NC}"
echo ""

# --- 编译 ---
echo -e "${BLUE}[STEP 1] Compiling Java sources...${NC}"
javac -cp "lib/jazzer_standalone.jar" -d out src/main/java/com/security/analysis/*.java
if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR] Compilation failed. Aborting.${NC}"
    exit 1
fi
echo -e "${GREEN}[SUCCESS] Compilation finished successfully.${NC}"
echo ""

# --- 设置Fuzzer运行参数 ---
# 根据详细程度设置传递给Java代码的系统属性
JAVA_OPTS=""
case $VERBOSE_LEVEL in
    all)
        JAVA_OPTS="-Dfuzzer.output.all=true -Dfuzzer.output.every=1"
        ;;
    interesting)
        JAVA_OPTS="-Dfuzzer.output.all=false -Dfuzzer.output.every=1000"
        ;;
    normal)
        # 默认模式，仅在发现漏洞时输出
        JAVA_OPTS="-Dfuzzer.output.all=false -Dfuzzer.output.every=999999999"
        ;;
esac

# --- 运行 Fuzzer ---
echo -e "${BLUE}[STEP 2] Starting Jazzer... (Press Ctrl+C to stop)${NC}"
echo -e "------------------------------------------------------------------"

# 核心运行命令
lib/jazzer \
    --cp="$CLASSPATH" \
    --target_class="$TARGET_CLASS" \
    --custom_hooks="$TARGET_HOOK" \
    --instrumentation_includes="com.mysql.cj.**" \
    --instrumentation_includes="com.security.**" \
    `# 修正: 必须添加 --add-modules=java.sql` \
    --jvm_args="--add-modules=java.sql" \
    `# 修正: 使用 -artifact_prefix 将所有发现保存到 findings/ 目录` \
    -artifact_prefix=findings/ \
    -max_len=256 \
    --keep_going=100 \
    -print_final_stats=1 \
    -use_value_profile=1 \
    "$JAVA_OPTS" \
    corpus/

# --- 结束 ---
echo ""
echo -e "------------------------------------------------------------------"
echo -e "${GREEN}[*] Fuzzing session completed.${NC}"

# 统计并报告发现
FINDING_COUNT=$(ls -1 findings/crash-* 2>/dev/null | wc -l | tr -d ' ')
echo -e "${BLUE}[SUMMARY] Found ${RED}${FINDING_COUNT}${BLUE} security issue(s).${NC}"
echo -e "${BLUE}[SUMMARY] Detailed reports are saved in the 'findings/' directory.${NC}"
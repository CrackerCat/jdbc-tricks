#!/bin/bash
# run_enhanced_fuzzer.sh - 增强版多CVE Fuzzer运行脚本

# --- 配置 ---
# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Fuzzer相关配置
TARGET_CLASS="com.security.analysis.EnhancedMySQLJdbcUrlFuzzer"
TARGET_HOOK="com.security.analysis.MysqlFileReadHook"
CLASSPATH="out:lib/mysql-connector-java-8.0.12.jar"

# 默认参数
VERBOSE_LEVEL="normal"
OUTPUT_FILE=""
STATS_INTERVAL="10000"

# --- 解析命令行参数 ---
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose) VERBOSE_LEVEL="all"; shift ;;
        -i|--interesting) VERBOSE_LEVEL="interesting"; shift ;;
        -s|--stats-only) VERBOSE_LEVEL="stats"; shift ;;
        -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
        -si|--stats-interval) STATS_INTERVAL="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  -v, --verbose          Show all generated URLs and properties"
            echo "  -i, --interesting      Show progress every 1000 iterations"
            echo "  -s, --stats-only       Only show statistics, no URL output"
            echo "  -o, --output FILE      Save console output to file as well"
            echo "  -si, --stats-interval N Print statistics every N iterations (default: 10000)"
            echo "  -h, --help             Show this help"
            echo ""
            echo "Harness Filter Management:"
            echo "  To add a new Harness filter:"
            echo "  1. Copy src/main/java/com/security/analysis/harness/cases/Harness_Template_Filter.java"
            echo "  2. Rename and modify it for your specific Harness"
            echo "  3. Place it in the same directory"
            echo "  4. Run this script - the new filter will be automatically loaded"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# --- 准备工作 ---
echo -e "${BLUE}[*] Creating directories: findings, corpus, logs, out...${NC}"
mkdir -p findings corpus logs out

# 设置输出重定向
if [ -n "$OUTPUT_FILE" ]; then
    exec &> >(tee -a "$OUTPUT_FILE")
fi

# --- 打印启动信息 ---
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║      Enhanced MySQL JDBC URL Fuzzer - Multi-CVE Mode       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo -e "${BLUE}[CONFIG] Verbose Level:${NC}    ${YELLOW}$VERBOSE_LEVEL${NC}"
echo -e "${BLUE}[CONFIG] Stats Interval:${NC}   ${YELLOW}$STATS_INTERVAL${NC}"
echo -e "${BLUE}[CONFIG] Log File:${NC}         ${YELLOW}${OUTPUT_FILE:-console}${NC}"
echo ""

# --- 检查CVE过滤器 ---
echo -e "${CYAN}[STEP 1] Checking Harness filters...${NC}"
CVE_FILTER_DIR="src/main/java/com/security/analysis/harness/cases"
CVE_FILTER_COUNT=$(find "$CVE_FILTER_DIR" -name "Harness_*_Filter.java" 2>/dev/null | wc -l | tr -d ' ')

if [ "$CVE_FILTER_COUNT" -eq 0 ]; then
    echo -e "${YELLOW}[WARNING] No Harness filters found in $CVE_FILTER_DIR${NC}"
    echo -e "${YELLOW}[WARNING] Only the default Harness CVE-2025-27103 filter will be used.${NC}"
else
    echo -e "${GREEN}[SUCCESS] Found $CVE_FILTER_COUNT Harness CVE filter(s):${NC}"
    find "$CVE_FILTER_DIR" -name "Harness_*_Filter.java" -exec basename {} \; | sed 's/\.java$//' | sed 's/^/  - /'
fi
echo ""

# --- 编译 ---
echo -e "${CYAN}[STEP 2] Compiling Java sources...${NC}"

# 重要修正：编译所有必要的文件，包括接口和管理器
javac -cp "lib/jazzer_standalone.jar" -d out \
    src/main/java/com/security/analysis/*.java \
    src/main/java/com/security/analysis/harness/*.java \
    src/main/java/com/security/analysis/harness/cases/*.java

if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR] Compilation failed. Aborting.${NC}"
    exit 1
fi
echo -e "${GREEN}[SUCCESS] Compilation finished successfully.${NC}"
echo ""

# --- 设置Fuzzer运行参数 ---
JAVA_OPTS=""
case $VERBOSE_LEVEL in
    all)
        JAVA_OPTS="-Dfuzzer.output.all=true -Dfuzzer.output.every=1"
        ;;
    interesting)
        JAVA_OPTS="-Dfuzzer.output.all=false -Dfuzzer.output.every=1000"
        ;;
    stats)
        JAVA_OPTS="-Dfuzzer.stats.only=true -Dfuzzer.output.every=$STATS_INTERVAL"
        ;;
    normal)
        JAVA_OPTS="-Dfuzzer.output.all=false -Dfuzzer.output.every=$STATS_INTERVAL"
        ;;
esac

# --- 运行 Fuzzer ---
echo -e "${CYAN}[STEP 3] Starting Enhanced Jazzer... (Press Ctrl+C to stop)${NC}"
echo -e "${PURPLE}[INFO] The fuzzer will automatically test all loaded CVE filters${NC}"
echo -e "${PURPLE}[INFO] Statistics will be printed every $STATS_INTERVAL iterations${NC}"
echo -e "------------------------------------------------------------------"

# 核心运行命令
lib/jazzer \
    --cp="$CLASSPATH" \
    --target_class="$TARGET_CLASS" \
    --custom_hooks="$TARGET_HOOK" \
    --instrumentation_includes="com.mysql.cj.**" \
    --instrumentation_includes="com.security.**" \
    --jvm_args="--add-modules=java.sql" \
    -artifact_prefix=findings/ \
    -max_len=512 \
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
FINDING_COUNT=$(ls -1 findings/crash-* findings/CVE-* 2>/dev/null | wc -l | tr -d ' ')
echo -e "${BLUE}[SUMMARY] Found ${RED}${FINDING_COUNT}${BLUE} security issue(s).${NC}"
echo -e "${BLUE}[SUMMARY] Detailed reports are saved in the 'findings/' directory.${NC}"

# 显示每个CVE的发现
echo -e "${CYAN}[SUMMARY] Findings by Harness :${NC}"
for cve in $(ls findings/CVE-* 2>/dev/null | grep -o 'CVE-[0-9]\{4\}-[0-9]\+' | sort -u); do
    count=$(ls findings/$cve-* 2>/dev/null | wc -l | tr -d ' ')
    echo -e "  ${YELLOW}$cve:${NC} $count bypass(es) found"
done
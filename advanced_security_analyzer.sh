#!/bin/bash

# ==========================================================================
# Advanced Security Analyzer Script - Instruction Section
# ==========================================================================

# Add this section at the end of your script, after all the function definitions
# and before the main execution section.

# ==========================================================================
# INSTRUCTIONS AND USAGE INFORMATION
# ==========================================================================

function display_help() {
    echo -e "\n${BOLD}${WHITE}Advanced Security Analyzer${RESET} - Version 1.0.0"
    echo -e "${BLUE}===========================================================================${RESET}"
    echo -e "${BOLD}DESCRIPTION:${RESET}"
    echo -e "  A comprehensive security analysis tool for Linux systems that performs"
    echo -e "  advanced security checks including memory forensics, rootkit detection,"
    echo -e "  network traffic analysis, and container security scanning."
    echo
    echo -e "${BOLD}USAGE:${RESET}"
    echo -e "  ./advanced_security_analyzer.sh [OPTIONS]"
    echo
    echo -e "${BOLD}OPTIONS:${RESET}"
    echo -e "  ${GREEN}-h, --help${RESET}               Show this help message"
    echo -e "  ${GREEN}-a, --all${RESET}                Run all security checks"
    echo -e "  ${GREEN}-m, --memory${RESET}             Run memory analysis only"
    echo -e "  ${GREEN}-r, --rootkit${RESET}            Run rootkit detection only"
    echo -e "  ${GREEN}-n, --network${RESET}            Run network analysis only"
    echo -e "  ${GREEN}-c, --container${RESET}          Run container security checks only"
    echo -e "  ${GREEN}-v, --verbose${RESET}            Enable verbose output"
    echo -e "  ${GREEN}-q, --quiet${RESET}              Minimal output (summary only)"
    echo -e "  ${GREEN}-o, --output [FILE]${RESET}      Write report to specified file"
    echo -e "  ${GREEN}--no-cleanup${RESET}             Keep temporary files"
    echo
    echo -e "${BOLD}EXAMPLES:${RESET}"
    echo -e "  ${YELLOW}# Run all security checks${RESET}"
    echo -e "  sudo ./advanced_security_analyzer.sh --all"
    echo
    echo -e "  ${YELLOW}# Run rootkit detection only${RESET}"
    echo -e "  sudo ./advanced_security_analyzer.sh --rootkit"
    echo
    echo -e "  ${YELLOW}# Run memory and network analysis with verbose output${RESET}"
    echo -e "  sudo ./advanced_security_analyzer.sh --memory --network --verbose"
    echo
    echo -e "  ${YELLOW}# Run container security checks and save output to file${RESET}"
    echo -e "  sudo ./advanced_security_analyzer.sh --container --output security_report.txt"
    echo
    echo -e "${BOLD}REQUIREMENTS:${RESET}"
    echo -e "  - Must be run as root (sudo)"
    echo -e "  - Required tools: volatility, tcpdump, lsof, strings, grep, awk, docker (for container checks)"
    echo
    echo -e "${BOLD}SCRIPT INTEGRITY:${RESET}"
    echo -e "  To verify the integrity of this script, run:"
    echo -e "  ${YELLOW}sha256sum advanced_security_analyzer.sh${RESET}"
    echo -e "  Compare the output with the expected hash value."
    echo
    echo -e "${BOLD}VERSION INFORMATION:${RESET}"
    echo -e "  Version:      1.0.0"
    echo -e "  Release Date: $(date +%Y-%m-%d)"
    echo -e "  License:      MIT"
    echo
    echo -e "${BOLD}CONTACT INFORMATION:${RESET}"
    echo -e "  Author:       Security Team"
    echo -e "  Email:        security@example.com"
    echo -e "  Website:      https://security.example.com"
    echo -e "  Bug Reports:  https://github.com/example/security-analyzer/issues"
    echo -e "${BLUE}===========================================================================${RESET}"
}

function verify_script_integrity() {
    local script_path="$0"
    local current_hash=$(sha256sum "$script_path" | awk '{print $1}')
    
    echo -e "\n${BOLD}${BLUE}Script Integrity Check${RESET}"
    echo -e "${YELLOW}Current hash:${RESET} $current_hash"
    
    # Store this hash somewhere safe for future comparison
    # You can implement additional integrity checks here
    
    echo -e "${GREEN}To verify this script in the future, compare the hash with a trusted source.${RESET}"
    echo -e "For enhanced security, consider signing the script with GPG."
}

# Add this to your main execution section
# if [[ "$1" == "--verify" ]]; then
#     verify_script_integrity
#     exit 0
# fi

# Note: Make this script executable by running:
# chmod +x advanced_security_analyzer.sh

# ==========================================================================
# END OF INSTRUCTION SECTION
# ==========================================================================

#!/bin/bash
# 
# advanced_security_analyzer.sh - v1.0
#
# Advanced Security Analysis Tool for Linux Systems
# Author: Security Analysis Team
# License: MIT
#
# Description:
#   Performs comprehensive security analysis of Linux systems, including
#   memory forensics, rootkit detection, network analysis, container security,
#   an
#
# advanced_security_analyzer.sh
# 
# Advanced Security Analysis Tool for Linux Systems
# Performs in-depth security analysis including:
# - Memory forensics
# - Deep rootkit detection
# - Network traffic analysis
# - Container security
# - Custom malware signature detection
#
# Usage: sudo ./advanced_security_analyzer.sh [options]
#
# Dependencies: volatility, tcpdump, yara, docker, lsof, strings, objdump, strace
#

set -o pipefail

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Temporary file locations
TEMP_DIR="/tmp/security_analysis_$(date +%s)"
LOG_FILE="$TEMP_DIR/security_analysis.log"
REPORT_FILE="security_report_$(hostname)_$(date +%F).txt"
SIGNATURE_DIR="$TEMP_DIR/signatures"
MEMORY_DUMP="$TEMP_DIR/memory.dmp"

# Tool paths (modify these if your tools are in different locations)
VOLATILITY_PATH=$(which volatility3 2>/dev/null || which vol.py 2>/dev/null || echo "/usr/local/bin/volatility3")
TCPDUMP_PATH=$(which tcpdump)
YARA_PATH=$(which yara)
DOCKER_PATH=$(which docker)

# Default options
PERFORM_MEMORY_ANALYSIS=false
PERFORM_ROOTKIT_DETECTION=false
PERFORM_NETWORK_ANALYSIS=false
PERFORM_CONTAINER_ANALYSIS=false
PERFORM_MALWARE_DETECTION=false
PERFORM_ALL=false
QUIET_MODE=false
DEBUG_MODE=false
CAPTURE_DURATION=60  # Default network capture duration in seconds

# Custom malware signatures (YARA rules)
YARA_RULES="
rule Suspicious_Shell_Commands {
    strings:
        $cmd1 = \"wget http\" nocase
        $cmd2 = \"curl http\" nocase
        $cmd3 = \"chmod +x\" nocase
        $cmd4 = \"nc -e\" nocase
        $cmd5 = \"/dev/tcp/\" nocase
        $cmd6 = \"bash -i\" nocase
        $crypto1 = \"miner\" nocase
        $crypto2 = \"monero\" nocase
        $crypto3 = \"bitcoin\" nocase
    condition:
        (2 of ($cmd*)) or (any of ($crypto*) and any of ($cmd*))
}

rule Hidden_Executable {
    strings:
        $s1 = \"#!/\" nocase
        $s2 = \".so\"
        $s3 = \"ELF\"
    condition:
        any of them and filename matches /\\\\..+/
}

rule Suspicious_Cron {
    strings:
        $s1 = \"* * * * *\" nocase
        $s2 = \"@daily\" nocase
        $s3 = \"curl\" nocase
        $s4 = \"wget\" nocase
        $s5 = \"|\" nocase
        $s6 = \">\" nocase
        $s7 = \"&\" nocase
        $s8 = \".sh\" nocase
    condition:
        ($s1 or $s2) and (2 of ($s3, $s4, $s5, $s6, $s7, $s8))
}

rule Suspicious_Library {
    strings:
        $s1 = \"dlopen\" nocase
        $s2 = \"dlsym\" nocase
        $s3 = \"ptrace\" nocase
        $s4 = \"execve\" nocase
    condition:
        2 of them
}

rule Suspicious_Network_Activity {
    strings:
        $s1 = \"connect(\" nocase
        $s2 = \"socket(\" nocase
        $s3 = \"bind(\" nocase
        $s4 = \"0.0.0.0\" nocase
        $s5 = \"6666\" nocase
        $s6 = \"4444\" nocase
    condition:
        ($s1 and $s2) and (any of ($s4, $s5, $s6))
}
"

# Initialize
function initialize() {
    echo -e "${BLUE}${BOLD}[+] Initializing Advanced Security Analyzer${NC}"
    
    # Check dependencies
    local missing_deps=()
    
    # Essential tools
    for tool in strings grep awk sed lsof ps netstat find; do
        if ! command -v $tool &>/dev/null; then
            missing_deps+=("$tool")
        fi
    done
    
    # Advanced tools with fallbacks
    if ! command -v $TCPDUMP_PATH &>/dev/null; then
        log_warning "tcpdump not found. Network traffic analysis will be limited."
    fi
    
    if [[ $PERFORM_MEMORY_ANALYSIS == true ]] && ! command -v $VOLATILITY_PATH &>/dev/null; then
        log_warning "Volatility not found. Memory analysis will be limited."
    fi
    
    if [[ $PERFORM_MALWARE_DETECTION == true ]] && ! command -v $YARA_PATH &>/dev/null; then
        log_warning "YARA not found. Custom signature detection will be limited."
    fi
    
    if [[ $PERFORM_CONTAINER_ANALYSIS == true ]] && ! command -v $DOCKER_PATH &>/dev/null; then
        log_warning "Docker not found. Container analysis will be skipped."
        PERFORM_CONTAINER_ANALYSIS=false
    fi
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing essential dependencies: ${missing_deps[*]}"
        echo -e "${RED}Please install missing dependencies and try again.${NC}"
        exit 1
    fi
    
    # Create temp directory
    mkdir -p "$TEMP_DIR" "$SIGNATURE_DIR"
    if [[ $? -ne 0 ]]; then
        log_error "Failed to create temporary directory: $TEMP_DIR"
        exit 1
    fi
    
    # Initialize log file
    echo "Advanced Security Analysis started at $(date)" > "$LOG_FILE"
    echo "System: $(uname -a)" >> "$LOG_FILE"
    
    # Create YARA signature files if YARA is available
    if command -v $YARA_PATH &>/dev/null; then
        echo "$YARA_RULES" > "$SIGNATURE_DIR/malware.yar"
    fi
    
    echo -e "${GREEN}Initialization complete. Starting analysis...${NC}"
    echo -e "Temporary files stored in: $TEMP_DIR\n"
}

# Logging functions
function log_info() {
    echo -e "${BLUE}[INFO] $1${NC}"
    echo "[INFO] $(date +"%Y-%m-%d %H:%M:%S") - $1" >> "$LOG_FILE"
}

function log_success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
    echo "[SUCCESS] $(date +"%Y-%m-%d %H:%M:%S") - $1" >> "$LOG_FILE"
}

function log_warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
    echo "[WARNING] $(date +"%Y-%m-%d %H:%M:%S") - $1" >> "$LOG_FILE"
}

function log_error() {
    echo -e "${RED}[ERROR] $1${NC}"
    echo "[ERROR] $(date +"%Y-%m-%d %H:%M:%S") - $1" >> "$LOG_FILE"
}

function log_debug() {
    if [[ $DEBUG_MODE == true ]]; then
        echo -e "${MAGENTA}[DEBUG] $1${NC}"
        echo "[DEBUG] $(date +"%Y-%m-%d %H:%M:%S") - $1" >> "$LOG_FILE"
    fi
}

function cleanup() {
    log_info "Cleaning up temporary files..."
    rm -rf "$TEMP_DIR"
    log_success "Cleanup complete."
}

function print_section_header() {
    local title="$1"
    local width=80
    local padding=$(( (width - ${#title} - 4) / 2 ))
    local line=$(printf "%${width}s" | tr ' ' '=')
    
    echo -e "\n${CYAN}${line}${NC}"
    echo -e "${CYAN}$(printf "%${padding}s" | tr ' ' '=')" \
          "${BOLD} ${title} ${NC}${CYAN}" \
          "$(printf "%${padding}s" | tr ' ' '=')${NC}"
    echo -e "${CYAN}${line}${NC}\n"
    
    echo -e "\n=== $title ===" >> "$REPORT_FILE"
}

#===========================================
# 1. Memory Forensics Functions
#===========================================

function perform_memory_analysis() {
    print_section_header "MEMORY FORENSICS"
    
    log_info "Starting memory analysis..."
    
    # Check if we have memory acquisition capabilities
    if ! command -v "$VOLATILITY_PATH" &>/dev/null && ! command -v "dd" &>/dev/null; then
        log_error "No memory forensics tools available. Skipping memory analysis."
        return 1
    fi
    
    # Try to create a memory dump if not already provided
    if [[ ! -f "$MEMORY_DUMP" ]]; then
        log_info "Attempting to create memory dump..."
        
        # Check if we can access /dev/mem or /proc/kcore
        if [[ -r "/dev/mem" ]]; then
            log_info "Using /dev/mem for memory acquisition"
            dd if=/dev/mem of="$MEMORY_DUMP" bs=1M count=1024 2>/dev/null
            if [[ $? -ne 0 ]]; then
                log_error "Failed to dump memory from /dev/mem"
            fi
        elif [[ -r "/proc/kcore" ]]; then
            log_info "Using /proc/kcore for memory acquisition"
            dd if=/proc/kcore of="$MEMORY_DUMP" bs=1M count=1024 2>/dev/null
            if [[ $? -ne 0 ]]; then
                log_error "Failed to dump memory from /proc/kcore"
            fi
        else
            log_warning "Cannot access memory devices. Limited memory analysis will be performed."
            # We'll proceed with live memory analysis
        fi
    fi
    
    # Basic memory analysis using strings and grep
    log_info "Performing basic memory string analysis..."
    
    echo -e "\n## Basic Memory String Analysis" >> "$REPORT_FILE"
    
    # Look for network connections in memory
    log_info "Searching for network indicators in memory..."
    {
        if [[ -f "$MEMORY_DUMP" ]]; then
            strings "$MEMORY_DUMP" | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}"
        else
            cat /proc/*/maps | strings | grep -E "([0-9]{1,3}[\.]){3}[0-9]{1,3}"
        fi
    } | sort | uniq > "$TEMP_DIR/memory_ip_addresses.txt"
    
    if [[ -s "$TEMP_DIR/memory_ip_addresses.txt" ]]; then
        log_info "Found $(wc -l < "$TEMP_DIR/memory_ip_addresses.txt") potential IP addresses in memory"
        echo -e "IP Addresses found in memory:" >> "$REPORT_FILE"
        cat "$TEMP_DIR/memory_ip_addresses.txt" >> "$REPORT_FILE"
    fi
    
    # Look for possible passwords and sensitive data
    log_info "Searching for sensitive data patterns in memory..."
    {
        if [[ -f "$MEMORY_DUMP" ]]; then
            strings "$MEMORY_DUMP" 
        else
            cat /proc/*/maps 2>/dev/null | strings
        fi
    } | grep -E "(password|credentials|secret|key=|token=)" | sort | uniq > "$TEMP_DIR/memory_sensitive.txt"
    
    if [[ -s "$TEMP_DIR/memory_sensitive.txt" ]]; then
        log_warning "Found $(wc -l < "$TEMP_DIR/memory_sensitive.txt") potential sensitive strings in memory"
        echo -e "Sensitive patterns found in memory (investigate further):" >> "$REPORT_FILE"
        head -n 50 "$TEMP_DIR/memory_sensitive.txt" >> "$REPORT_FILE"
        echo -e "... (truncated) ..." >> "$REPORT_FILE"
    fi
    
    # Advanced memory analysis using volatility if available
    if command -v "$VOLATILITY_PATH" &>/dev/null && [[ -f "$MEMORY_DUMP" ]]; then
        log_info "Performing advanced memory analysis with Volatility..."
        
        echo -e "\n## Volatility Memory Analysis" >> "$REPORT_FILE"
        
        # Get running processes
        log_info "Analyzing process list from memory dump..."
        $VOLATILITY_PATH -f "$MEMORY_DUMP" windows.pslist.PsList 2>/dev/null > "$TEMP_DIR/vol_pslist.txt"
        $VOLATILITY_PATH -f "$MEMORY_DUMP" linux.pslist.PsList 2>/dev/null >> "$TEMP_DIR/vol_pslist.txt"
        
        if [[ -s "$TEMP_DIR/vol_pslist.txt" ]]; then
            echo -e "Process list from memory dump:" >> "$REPORT_FILE"
            cat "$TEMP_DIR/vol_pslist.txt" >> "$REPORT_FILE"
        fi
        
        # Get network connections
        log_info "Analyzing network connections from memory dump..."
        $VOLATILITY_PATH -f "$MEMORY_DUMP" windows.netscan.NetScan 2>/dev/null > "$TEMP_DIR/vol_netscan.txt"
        $VOLATILITY_PATH -f "$MEMORY_DUMP" linux.netstat.NetStat 2>/dev/null >> "$TEMP_DIR/vol_netscan.txt"
        
        if [[ -s "$TEMP_DIR/vol_netscan.txt" ]]; then
            echo -e "\nNetwork connections from memory dump:" >> "$REPORT_FILE"
            cat "$TEMP_DIR/vol_netscan.txt" >> "$REPORT_FILE"
        fi
        
        # Find injected code
        log_info "Looking for code injection in memory dump..."
        $VOLATILITY_PATH -f "$MEMORY_DUMP" windows.malfind.Malfind 2>/dev/null > "$TEMP_DIR/vol_malfind.txt"
        $VOLATILITY_PATH -f "$MEMORY_DUMP" linux.malfind.Malfind 2>/dev/null >> "$TEMP_DIR/vol_malfind.txt"
        
        if [[ -s "$TEMP_DIR/vol_malfind.txt" ]]; then
            log_warning "Potential code injection detected in memory!"
            echo -e "\nPotential code injection found:" >> "$REPORT_FILE"
            cat "$TEMP_DIR/vol_malfind.txt" >> "$REPORT_FILE"
        fi
    fi

    # Advanced malware detection patterns in memory
    log_info "Searching for known malware patterns in memory..."
    
    # Define malware detection patterns
    local malware_patterns=(
        # Command and control patterns
        "connect.*:4[4-5][0-9][0-9]"
        "beacon.*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"
        # Fileless malware indicators
        "VirtualAlloc.*0x00000040"
        "CreateRemoteThread"
        "HeapCreate.*0x40000"
        "memfd_create"
        # Encryption related
        "AES_"
        "RC4"
        "XOR.*0x[0-9a-f]"
        # Persistence mechanisms
        "CurrentVersion\\\\Run"
        "schtasks /create"
        "crontab -e"
        # Common payload strings
        "powershell.*bypass"
        "cmd.exe /c"
        "eval.*base64_decode"
        "bash.*base64.*decode"
        # Rootkit indicators
        "hide.*process"
        "syscall.*hook"
        "kernel.*module.*hide"
        # Cryptocurrency mining indicators
        "stratum+tcp://"
        "cryptonight"
        "minerd"
        "coinhive"
        "monero"
    )
    
    echo -e "\n## Memory Malware Pattern Detection" >> "$REPORT_FILE"
    
    # Check memory for malware patterns
    local detected_count=0
    local memory_source=""
    
    if [[ -f "$MEMORY_DUMP" ]]; then
        memory_source="$MEMORY_DUMP"
    else
        # Create a combined memory dump from process mappings
        for procmap in /proc/*/maps; do
            pid=$(echo "$procmap" | cut -d'/' -f3)
            if [[ -r "/proc/$pid/mem" ]]; then
                cat "/proc/$pid/mem" 2>/dev/null >> "$TEMP_DIR/live_memory.dump"
            fi
        done
        if [[ -f "$TEMP_DIR/live_memory.dump" ]]; then
            memory_source="$TEMP_DIR/live_memory.dump"
        fi
    fi
    
    if [[ -n "$memory_source" ]]; then
        for pattern in "${malware_patterns[@]}"; do
            log_debug "Searching for pattern: $pattern"
            result=$(strings "$memory_source" | grep -E "$pattern" | sort | uniq)
            if [[ -n "$result" ]]; then
                detected_count=$((detected_count + 1))
                echo -e "\nDetected suspicious pattern: $pattern" >> "$REPORT_FILE"
                echo "$result" | head -n 20 >> "$REPORT_FILE"
                echo -e "(showing first 20 matches only)" >> "$REPORT_FILE"
                
                log_warning "Found suspicious pattern in memory: $pattern"
            fi
        done
    else
        log_warning "No memory source available for malware pattern analysis"
    fi
    
    # Use YARA for advanced pattern matching if available
    if command -v "$YARA_PATH" &>/dev/null && [[ -f "$SIGNATURE_DIR/malware.yar" ]]; then
        log_info "Performing YARA scan on memory..."
        if [[ -n "$memory_source" ]]; then
            "$YARA_PATH" -f "$SIGNATURE_DIR/malware.yar" "$memory_source" > "$TEMP_DIR/yara_memory_scan.txt"
            
            if [[ -s "$TEMP_DIR/yara_memory_scan.txt" ]]; then
                detected_count=$((detected_count + $(wc -l < "$TEMP_DIR/yara_memory_scan.txt")))
                log_warning "YARA detected potential malware in memory!"
                echo -e "\nYARA detection results:" >> "$REPORT_FILE"
                cat "$TEMP_DIR/yara_memory_scan.txt" >> "$REPORT_FILE"
            else
                log_success "No YARA matches found in memory"
            fi
        fi
    fi
    
    # Analyze loaded libraries for suspicious patterns
    log_info "Analyzing loaded libraries for suspicious patterns..."
    lsof -n | grep -E "\.so|\.dll" | sort | uniq > "$TEMP_DIR/loaded_libraries.txt"
    
    if [[ -s "$TEMP_DIR/loaded_libraries.txt" ]]; then
        # Look for libraries loaded from suspicious locations
        grep -E "/tmp|/dev/shm|/var/tmp|/private/tmp|/run/shm" "$TEMP_DIR/loaded_libraries.txt" > "$TEMP_DIR/suspicious_libraries.txt"
        
        if [[ -s "$TEMP_DIR/suspicious_libraries.txt" ]]; then
            detected_count=$((detected_count + $(wc -l < "$TEMP_DIR/suspicious_libraries.txt")))
            log_warning "Found libraries loaded from suspicious locations!"
            echo -e "\nSuspicious libraries loaded from unusual locations:" >> "$REPORT_FILE"
            cat "$TEMP_DIR/suspicious_libraries.txt" >> "$REPORT_FILE"
        fi
    fi
    
    # Report summary
    echo -e "\n## Memory Analysis Summary" >> "$REPORT_FILE"
    if [[ $detected_count -gt 0 ]]; then
        log_warning "Memory analysis complete. Found $detected_count suspicious indicators."
        echo -e "Total suspicious indicators found: $detected_count\nRecommendation: Review the detailed findings and investigate further." >> "$REPORT_FILE"
    else
        log_success "Memory analysis complete. No suspicious indicators found."
        echo -e "No suspicious indicators found in memory analysis.\nRecommendation: Continue with regular security monitoring." >> "$REPORT_FILE"
    fi
    
    return 0
}

#===========================================
# 2. Rootkit Detection Functions
#===========================================

function rootkit_detection() {
    print_section_header "ROOTKIT DETECTION"
    
    log_info "Starting advanced rootkit detection..."
    local threats_found=0
    
    # Create rootkit detection results directory
    mkdir -p "$TEMP_DIR/rootkit_detection"
    
    echo -e "## Rootkit Detection Results" >> "$REPORT_FILE"
    
    # 1. Kernel module analysis
    log_info "Analyzing loaded kernel modules..."
    echo -e "\n### Kernel Module Analysis" >> "$REPORT_FILE"
    
    # Get list of loaded modules
    lsmod > "$TEMP_DIR/rootkit_detection/loaded_modules.txt"
    
    # Check for known malicious kernel modules
    local suspicious_modules=(
        "hide_proc" "suterusu" "adore" "modhide" "kbeast" 
        "ipsecs" "klisn" "phide" "kis" "kitko" "rpldev"
        "enyelkm" "logdel" "cleaner" "dma" "ftshh" "phalanx"
        "redhat" "reset" "wkmr" "avatar" "nuclearmod" "op"
        "snd_page_alloc" "pfact" "kmodp" "mmap_mod" "tuxkit"
        "nnf" "kbdv3" "kbd_notifier" "simp" "hide_module"
    )
    
    for module in "${suspicious_modules[@]}"; do
        if grep -q "$module" "$TEMP_DIR/rootkit_detection/loaded_modules.txt"; then
            log_warning "Found potentially malicious kernel module: $module"
            echo -e "SUSPICIOUS MODULE DETECTED: $module" >> "$REPORT_FILE"
            threats_found=$((threats_found + 1))
        fi
    done
    
    # Check for modules hiding other modules (size mismatch)
    log_info "Checking for hidden kernel modules..."
    
    # Compare modules list with /proc/modules
    local modules_count_lsmod=$(wc -l < "$TEMP_DIR/rootkit_detection/loaded_modules.txt")
    local modules_count_proc=$(grep -c "" /proc/modules)
    
    if [[ $modules_count_lsmod -ne $modules_count_proc ]]; then
        log_warning "Module count mismatch: lsmod shows $modules_count_lsmod but /proc/modules shows $modules_count_proc"
        echo -e "SUSPICIOUS: Module count mismatch between lsmod and /proc/modules" >> "$REPORT_FILE"
        echo -e "This may indicate hidden kernel modules" >> "$REPORT_FILE"
        threats_found=$((threats_found + 1))
    fi
    
    # Compare with modules in /sys/module
    local modules_count_sys=$(find /sys/module -maxdepth 1 -type d | wc -l)
    if [[ $((modules_count_sys - 1)) -ne $modules_count_lsmod ]]; then
        log_warning "Module count mismatch: lsmod shows $modules_count_lsmod but /sys/module shows $((modules_count_sys - 1))"
        echo -e "SUSPICIOUS: Module count mismatch between lsmod and /sys/module" >> "$REPORT_FILE"
        threats_found=$((threats_found + 1))
    fi
    
    # 2. System call hooking detection
    log_info "Checking for system call table hooks..."
    echo -e "\n### System Call Hook Detection" >> "$REPORT_FILE"
    
    # Examine system call table for suspicious entries if /proc/kallsyms is readable
    if [[ -r "/proc/kallsyms" ]]; then
        # Get system call addresses
        grep -E "sys_|syscall" /proc/kallsyms > "$TEMP_DIR/rootkit_detection/syscalls.txt"
        
        # Look for non-standard addresses
        # Check if syscalls point outside the kernel (potential hooks)
        local normal_range=$(grep " T " /proc/kallsyms | grep "kernel" | head -n 1 | awk '{print $1}' | cut -c 1-6)
        
        if [[ -n "$normal_range" ]]; then
            grep -v "ffffffff${normal_range}" "$TEMP_DIR/rootkit_detection/syscalls.txt" | grep "sys_" > "$TEMP_DIR/rootkit_detection/suspicious_syscalls.txt"
            
            if [[ -s "$TEMP_DIR/rootkit_detection/suspicious_syscalls.txt" ]]; then
                log_warning "Found potentially hooked system calls"
                echo -e "Potentially hooked system calls detected:" >> "$REPORT_FILE"
                cat "$TEMP_DIR/rootkit_detection/suspicious_syscalls.txt" >> "$REPORT_FILE"
                threats_found=$((threats_found + 1))
            fi
        fi
    else
        log_warning "Cannot access /proc/kallsyms. Limited syscall hooking detection."
        echo -e "Limited syscall analysis - /proc/kallsyms not accessible" >> "$REPORT_FILE"
    fi
    
    # 3. Hidden process discovery
    log_info "Searching for hidden processes..."
    echo -e "\n### Hidden Process Detection" >> "$REPORT_FILE"
    
    # Get process list using different methods
    ps aux > "$TEMP_DIR/rootkit_detection/ps_processes.txt"
    ls -la /proc/ | grep -E "^d" | grep -E "[0-9]+" | awk '{print $9}' > "$TEMP_DIR/rootkit_detection/proc_processes.txt"
    
    # Compare process counts
    local ps_count=$(grep -c "" "$TEMP_DIR/rootkit_detection/ps_processes.txt")
    local proc_count=$(grep -c "" "$TEMP_DIR/rootkit_detection/proc_processes.txt")
    
    if [[ $ps_count -lt $proc_count ]]; then
        log_warning "Found potential hidden processes: ps shows $ps_count processes but /proc shows $proc_count"
        echo -e "HIDDEN PROCESSES DETECTED: ps command shows fewer processes than /proc directory" >> "$REPORT_FILE"
        
        # Find the hidden PIDs
        for pid in $(cat "$TEMP_DIR/rootkit_detection/proc_processes.txt"); do
            if ! grep -q "\\s${pid}\\s" "$TEMP_DIR/rootkit_detection/ps_processes.txt"; then
                if [[ -d "/proc/$pid" ]]; then
                    log_warning "Hidden process detected: PID $pid"
                    echo -e "Hidden PID: $pid" >> "$REPORT_FILE"
                    
                    # Try to get more info about the hidden process
                    if [[ -r "/proc/$pid/cmdline" ]]; then
                        local cmdline=$(tr -d '\0' < "/proc/$pid/cmdline")
                        echo -e "  Command line: $cmdline" >> "$REPORT_FILE"
                    fi
                    
                    if [[ -r "/proc/$pid/exe" ]]; then
                        local exe_path=$(readlink -f "/proc/$pid/exe")
                        echo -e "  Executable: $exe_path" >> "$REPORT_FILE"
                    fi
                    
                    # Check open files for this process
                    if [[ -r "/proc/$pid/fd" ]]; then
                        echo -e "  Open files:" >> "$REPORT_FILE"
                        ls -la "/proc/$pid/fd" 2>/dev/null | head -n 10 >> "$REPORT_FILE"
                    fi
                    
                    threats_found=$((threats_found + 1))
                fi
            fi
        done
    fi
    
    # 4. Check for DKOM (Direct Kernel Object Manipulation) signs
    log_info "Checking for DKOM and runtime patching signs..."
    echo -e "\n### DKOM Detection" >> "$REPORT_FILE"
    
    # Check /dev entries for suspicious devices
    ls -la /dev > "$TEMP_DIR/rootkit_detection/dev_entries.txt"
    grep -E "\.so|\.o|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" "$TEMP_DIR/rootkit_detection/dev_entries.txt" > "$TEMP_DIR/rootkit_detection/suspicious_dev_entries.txt"
    
    if [[ -s "$TEMP_DIR/rootkit_detection/suspicious_dev_entries.txt" ]]; then
        log_warning "Found suspicious /dev entries"
        echo -e "Suspicious /dev entries detected:" >> "$REPORT_FILE"
        cat "$TEMP_DIR/rootkit_detection/suspicious_dev_entries.txt" >> "$REPORT_FILE"
        threats_found=$((threats_found + 1))
    fi
    
    # 5. Check for unusual file hiding in common directories
    log_info "Checking for hidden files in common directories..."
    echo -e "\n### File Hiding Detection" >> "$REPORT_FILE"
    
    # Define locations to check for hidden files
    local directories_to_check=(
        "/etc" "/bin" "/sbin" "/usr/bin" "/usr/sbin" 
        "/lib" "/lib64" "/usr/lib" "/usr/lib64"
        "/var/log" "/var/spool" "/var/www" "/tmp" "/var/tmp"
    )
    
    # Create a list of found hidden files and directories
    > "$TEMP_DIR/rootkit_detection/hidden_files.txt"
    
    for dir in "${directories_to_check[@]}"; do
        if [[ -d "$dir" ]]; then
            log_debug "Checking directory: $dir"
            
            # Find hidden files in this directory
            find "$dir" -name ".*" -type f 2>/dev/null | grep -v -E "^\.$|^\.\.$|^\.git|^\.config" >> "$TEMP_DIR/rootkit_detection/hidden_files.txt"
            
            # Check for files with alternative data streams (attr xattrs on Linux)
            if command -v getfattr &>/dev/null; then
                find "$dir" -type f -exec getfattr -d {} 2>/dev/null \; | grep -E "user\." > "$TEMP_DIR/rootkit_detection/xattr_files.txt"
            fi
            
            # Look for directories with unusual permissions that might be hiding content
            find "$dir" -type d -perm -2000 -o -type d -perm -4000 2>/dev/null >> "$TEMP_DIR/rootkit_detection/setuid_dirs.txt"
        fi
    done
    
    # Report findings for hidden files
    if [[ -s "$TEMP_DIR/rootkit_detection/hidden_files.txt" ]]; then
        # Filter out common hidden files
        grep -v -E "\.gitignore|\.bashrc|\.bash_history|\.profile|\.viminfo" "$TEMP_DIR/rootkit_detection/hidden_files.txt" > "$TEMP_DIR/rootkit_detection/suspicious_hidden_files.txt"
        
        if [[ -s "$TEMP_DIR/rootkit_detection/suspicious_hidden_files.txt" ]]; then
            local suspicious_count=$(wc -l < "$TEMP_DIR/rootkit_detection/suspicious_hidden_files.txt")
            log_warning "Found $suspicious_count suspicious hidden files"
            echo -e "Suspicious hidden files detected:" >> "$REPORT_FILE"
            cat "$TEMP_DIR/rootkit_detection/suspicious_hidden_files.txt" >> "$REPORT_FILE"
            threats_found=$((threats_found + 1))
        fi
    fi
    
    # Check for files with xattrs (possible data hiding)
    if [[ -s "$TEMP_DIR/rootkit_detection/xattr_files.txt" ]]; then
        log_warning "Found files with extended attributes (possible data hiding)"
        echo -e "\nFiles with extended attributes:" >> "$REPORT_FILE"
        cat "$TEMP_DIR/rootkit_detection/xattr_files.txt" >> "$REPORT_FILE"
        threats_found=$((threats_found + 1))
    fi
    
    # Check for unusual setuid/setgid directories
    if [[ -s "$TEMP_DIR/rootkit_detection/setuid_dirs.txt" ]]; then
        log_warning "Found directories with setuid/setgid bits set"
        echo -e "\nDirectories with setuid/setgid bits (unusual):" >> "$REPORT_FILE"
        cat "$TEMP_DIR/rootkit_detection/setuid_dirs.txt" >> "$REPORT_FILE"
        threats_found=$((threats_found + 1))
    fi
    
    # 6. Check for file discrepancies using find and ls comparison
    log_info "Checking for file hiding through command manipulation..."
    
    # Select a directory to test
    local test_dir="/bin"
    if [[ -d "$test_dir" ]]; then
        # Get list with ls and find
        ls -la "$test_dir" | grep -v '^total' | awk '{print $9}' | sort > "$TEMP_DIR/rootkit_detection/ls_files.txt"
        find "$test_dir" -maxdepth 1 -type f -o -type d | sed "s|$test_dir/||g" | sort > "$TEMP_DIR/rootkit_detection/find_files.txt"
        
        # Compare file counts
        local ls_count=$(grep -v '^$' "$TEMP_DIR/rootkit_detection/ls_files.txt" | wc -l)
        local find_count=$(grep -v '^$' "$TEMP_DIR/rootkit_detection/find_files.txt" | wc -l)
        
        if [[ $ls_count -ne $find_count ]]; then
            log_warning "File count discrepancy: ls shows $ls_count files but find shows $find_count files in $test_dir"
            echo -e "\nPossible ls command manipulation detected. File counts don't match between ls and find in $test_dir" >> "$REPORT_FILE"
            echo -e "This could indicate an ls command rootkit that hides specific files." >> "$REPORT_FILE"
            
            # Find the specific files being hidden
            comm -13 "$TEMP_DIR/rootkit_detection/ls_files.txt" "$TEMP_DIR/rootkit_detection/find_files.txt" > "$TEMP_DIR/rootkit_detection/hidden_from_ls.txt"
            if [[ -s "$TEMP_DIR/rootkit_detection/hidden_from_ls.txt" ]]; then
                echo -e "\nFiles hidden from ls command:" >> "$REPORT_FILE"
                cat "$TEMP_DIR/rootkit_detection/hidden_from_ls.txt" >> "$REPORT_FILE"
            fi
            
            threats_found=$((threats_found + 1))
        fi
    fi
    
    # 7. Check for directory listing discrepancies
    log_info "Checking for directory listing discrepancies..."
    
    # Test directories
    local critical_dirs=("/etc" "/bin" "/sbin" "/lib" "/usr/bin")
    
    for dir in "${critical_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            # Get directory listing in two different ways
            ls -la "$dir" | grep -v '^total' | awk '{print $9}' | grep -v "^$" | sort > "$TEMP_DIR/rootkit_detection/ls_${dir//\//_}.txt"
            echo * | tr ' ' '\n' | sort > "$TEMP_DIR/rootkit_detection/echo_${dir//\//_}.txt"
            
            # Compare output
            if ! cmp -s "$TEMP_DIR/rootkit_detection/ls_${dir//\//_}.txt" "$TEMP_DIR/rootkit_detection/echo_${dir//\//_}.txt"; then
                log_warning "Directory listing discrepancy detected in $dir"
                echo -e "\nPossible file hiding detected in directory: $dir" >> "$REPORT_FILE"
                echo -e "Files listed by 'ls' but not by shell expansion, or vice versa. This indicates potential file hiding." >> "$REPORT_FILE"
                threats_found=$((threats_found + 1))
            fi
        fi
    done
    
    # 8. Check for timestamp inconsistencies (common in rootkits)
    log_info "Checking for timestamp inconsistencies..."
    
    # Check key system binaries
    local critical_binaries=(
        "/bin/ls" "/bin/ps" "/bin/netstat" "/bin/ss" "/bin/ip" 
        "/bin/bash" "/usr/bin/top" "/bin/login" "/bin/su" "/usr/bin/sudo"
    )
    
    for binary in "${critical_binaries[@]}"; do
        if [[ -f "$binary" ]]; then
            stat "$binary" > "$TEMP_DIR/rootkit_detection/stat_${binary//\//_}.txt"
            
            # Extract timestamps
            local modify_time=$(grep "Modify:" "$TEMP_DIR/rootkit_detection/stat_${binary//\//_}.txt" | awk '{print $2, $3}')
            local change_time=$(grep "Change:" "$TEMP_DIR/rootkit_detection/stat_${binary//\//_}.txt" | awk '{print $2, $3}')
            
            # Compare dates (change time should not be much newer than modify time for system binaries)
            local modify_epoch=$(date -d "$modify_time" +%s 2>/dev/null)
            local change_epoch=$(date -d "$change_time" +%s 2>/dev/null)
            
            if [[ -n "$modify_epoch" && -n "$change_epoch" ]]; then
                local diff=$((change_epoch - modify_epoch))
                
                # If change time is more than 1 day newer than modify time for system binaries, it's suspicious
                # (implies attributes were changed without modifying content - possible rootkit installation)
                if [[ $diff -gt 86400 ]]; then
                    log_warning "Suspicious timestamp discrepancy for $binary"
                    echo -e "\nSuspicious timestamp discrepancy for $binary:" >> "$REPORT_FILE"
                    echo -e "Modify: $modify_time\nChange: $change_time" >> "$REPORT_FILE"
                    echo -e "Change time is $(($diff / 86400)) days newer than modify time. This may indicate tampering." >> "$REPORT_FILE"
                    threats_found=$((threats_found + 1))
                fi
            fi
        fi
    done
    
    # Report summary
    echo -e "\n### Rootkit Detection Summary" >> "$REPORT_FILE"
    if [[ $threats_found -gt 0 ]]; then
        log_warning "Rootkit detection complete. Found $threats_found suspicious indicators."
        echo -e "Total suspicious indicators found: $threats_found\nRecommendation: Review the detailed findings and investigate further." >> "$REPORT_FILE"
    else
        log_success "Rootkit detection complete. No suspicious indicators found."
        echo -e "No suspicious rootkit indicators found.\nRecommendation: Continue with regular security monitoring." >> "$REPORT_FILE"
    fi
    
    return $threats_found
}

#===========================================
# 3. Network Analysis Functions
#===========================================

function network_analysis() {
    print_section_header "NETWORK TRAFFIC ANALYSIS"
    
    log_info "Starting deep network traffic analysis..."
    local threats_found=0
    
    # Create network analysis directory
    mkdir -p "$TEMP_DIR/network_analysis"
    
    echo -e "## Network Traffic Analysis Results" >> "$REPORT_FILE"
    
    # 1. Capture live network traffic if tcpdump is available
    if command -v "$TCPDUMP_PATH" &>/dev/null; then
        log_info "Capturing live network traffic for $CAPTURE_DURATION seconds..."
        echo -e "\n### Live Network Capture" >> "$REPORT_FILE"
        
        # Create pcap file
        "$TCPDUMP_PATH" -i any -nn -w "$TEMP_DIR/network_analysis/capture.pcap" -G $CAPTURE_DURATION -W 1 &>/dev/null &
        local tcpdump_pid=$!
        
        # Wait for capture to complete
        sleep 5
        echo -e "Capturing network traffic for $CAPTURE_DURATION seconds..." 
        sleep $(($CAPTURE_DURATION - 5))
        
        # Make sure tcpdump has terminated
        if ps -p $tcpdump_pid > /dev/null; then
            kill $tcpdump_pid 2>/dev/null
        fi
        
        # Analyze captured traffic
        if [[ -f "$TEMP_DIR/network_analysis/capture.pcap" ]]; then
            log_info "Analyzing captured network traffic..."
            
            # Basic statistics
            "$TCPDUMP_PATH" -r "$TEMP_DIR/network_analysis/capture.pcap" -nn | wc -l > "$TEMP_DIR/network_analysis/packet_count.txt"
            local packet_count=$(cat "$TEMP_DIR/network_analysis/packet_count.txt")
            
            echo -e "Captured $packet_count packets in $CAPTURE_DURATION seconds" >> "$REPORT_FILE"
            
            # Extract protocol statistics
            "$TCPDUMP_PATH" -r "$TEMP_DIR/network_analysis/capture.pcap" -nn > "$TEMP_DIR/network_analysis/full_capture.txt"
            
            # Count TCP/UDP/ICMP packets
            local tcp_count=$(grep -c " tcp " "$TEMP_DIR/network_analysis/full_capture.txt")
            local udp_count=$(grep -c " udp " "$TEMP_DIR/network_analysis/full_capture.txt")
            local icmp_count=$(grep -c " ICMP " "$TEMP_DIR/network_analysis/full_capture.txt")
            
            echo -e "Protocol distribution:\nTCP: $tcp_count\nUDP: $udp_count\nICMP: $icmp_count" >> "$REPORT_FILE"
            
            # Identify top talkers (IP addresses)
            log_info "Identifying top network talkers..."
            grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" "$TEMP_DIR/network_analysis/full_capture.txt" | 
            sort | uniq -c | sort -nr | head -n 10 > "$TEMP_DIR/network_analysis/top_talkers.txt"
            
            echo -e "\nTop network talkers:" >> "$REPORT_FILE"
            cat "$TEMP_DIR/network_analysis/top_talkers.txt" >> "$REPORT_FILE"
            
            # Identify unusual ports and services
            log_info "Analyzing ports and services..."
            grep " tcp " "$TEMP_DIR/network_analysis/full_capture.txt" | 
            grep -E -o " [0-9]{1,5} " | sort | uniq -c | sort -nr > "$TEMP_DIR/network_analysis/tcp_ports.txt"
            
            grep " udp " "$TEMP_DIR/network_analysis/full_capture.txt" | 
            grep -E -o " [0-9]{1,5} " | sort | uniq -c | sort -nr > "$TEMP_DIR/network_analysis/udp_ports.txt"
            
            echo -e "\nTCP ports detected:" >> "$REPORT_FILE"
            head -n 15 "$TEMP_DIR/network_analysis/tcp_ports.txt" >> "$REPORT_FILE"
            
            echo -e "\nUDP ports detected:" >> "$REPORT_FILE"
            head -n 15 "$TEMP_DIR/network_analysis/udp_ports.txt" >> "$REPORT_FILE"
            
            # Check for suspicious ports
            log_info "Checking for suspicious ports..."
            local suspicious_ports=(
                "1080" "4444" "5555" "6666" "6667" "6668" "6669" "7777" "8888" "9999"
                "23" "25" "111" "135" "445" "1433" "3306" "3389" "5900" "5901"
                "31337" "12345" "54321" "1337" "31415" "27374" "2222" "41414" "21554"
            )
            
            echo -e "\n### Suspicious Port Analysis" >> "$REPORT_FILE"
            local suspicious_port_found=false
            
            for port in "${suspicious_ports[@]}"; do
                if grep -q " $port " "$TEMP_DIR/network_analysis/tcp_ports.txt" || \
                   grep -q " $port " "$TEMP_DIR/network_analysis/udp_ports.txt"; then
                    log_warning "Suspicious port detected: $port"
                    echo -e "SUSPICIOUS PORT DETECTED: $port" >> "$REPORT_FILE"
                    suspicious_port_found=true
                    threats_found=$((threats_found + 1))
                fi
            done
            
            if [[ "$suspicious_port_found" == "false" ]]; then
                log_success "No suspicious ports detected in network capture"
                echo -e "No suspicious ports detected in network capture." >> "$REPORT_FILE"
            fi
            
            # Protocol anomaly detection
            log_info "Analyzing for protocol anomalies..."
            echo -e "\n### Protocol Anomaly Detection" >> "$REPORT_FILE"
            
            # Check for non-standard protocol behavior
            grep "malformed packet" "$TEMP_DIR/network_analysis/full_capture.txt" > "$TEMP_DIR/network_analysis/malformed_packets.txt"
            if [[ -s "$TEMP_DIR/network_analysis/malformed_packets.txt" ]]; then
                log_warning "Detected malformed packets in network traffic"
                echo -e "Malformed packets detected (possible protocol manipulation):" >> "$REPORT_FILE"
                cat "$TEMP_DIR/network_analysis/malformed_packets.txt" >> "$REPORT_FILE"
                threats_found=$((threats_found + 1))
            fi
            
            # Check for unusual HTTP methods
            grep -E "HTTP|GET|POST" "$TEMP_DIR/network_analysis/full_capture.txt" | \
            grep -v -E "GET|POST|HEAD|OPTIONS" > "$TEMP_DIR/network_analysis/unusual_http.txt"
            if [[ -s "$TEMP_DIR/network_analysis/unusual_http.txt" ]]; then
                log_warning "Detected unusual HTTP methods"
                echo -e "\nUnusual HTTP methods detected:" >> "$REPORT_FILE"
                cat "$TEMP_DIR/network_analysis/unusual_http.txt" >> "$REPORT_FILE"
                threats_found=$((threats_found + 1))
            fi
            
            # Check for traffic pattern anomalies (high volume of small packets)
            local small_packet_count=$(grep -c "length [1-9][0-9]:" "$TEMP_DIR/network_analysis/full_capture.txt")
            if [[ $small_packet_count -gt 100 ]]; then
                log_warning "High volume of small packets detected: $small_packet_count"
                echo -e "\nHigh volume of small packets detected: $small_packet_count" >> "$REPORT_FILE"
                echo -e "This may indicate covert channel communication or DoS activity" >> "$REPORT_FILE"
                threats_found=$((threats_found + 1))
            fi
        else
            log_warning "No packet capture file found. Skipping detailed traffic analysis."
            echo -e "Failed to capture network traffic for analysis." >> "$REPORT_FILE"
        fi
    else
        log_warning "tcpdump not available. Limited network analysis will be performed."
        echo -e "Limited network analysis - tcpdump not available" >> "$REPORT_FILE"
    fi
    
    # 2. Analyze current network connections
    log_info "Analyzing current network connections..."
    echo -e "\n### Current Network Connections" >> "$REPORT_FILE"
    
    # Get current connections using ss or netstat
    if command -v ss &>/dev/null; then
        ss -tuplan > "$TEMP_DIR/network_analysis/connections.txt"
    elif command -v netstat &>/dev/null; then
        netstat -tuplan > "$TEMP_DIR/network_analysis/connections.txt"
    else
        log_warning "Neither ss nor netstat are available. Limited connection analysis."
        echo -e "Limited connection analysis - network tools not available" >> "$REPORT_FILE"
    fi
    
    # List all listening ports
    if [[ -f "$TEMP_DIR/network_analysis/connections.txt" ]]; then
        grep "LISTEN" "$TEMP_DIR/network_analysis/connections.txt" > "$TEMP_DIR/network_analysis/listening_ports.txt"
        
        echo -e "Currently listening ports:" >> "$REPORT_FILE"
        cat "$TEMP_DIR/network_analysis/listening_ports.txt" >> "$REPORT_FILE"
        
        # Check for ports listening on all interfaces (0.0.0.0 or ::)
        grep -E "0.0.0.0|::" "$TEMP_DIR/network_analysis/listening_ports.txt" > "$TEMP_DIR/network_analysis/all_interfaces.txt"
        
        if [[ -s "$TEMP_DIR/network_analysis/all_interfaces.txt" ]]; then
            log_warning "Found services listening on all interfaces"
            echo -e "\nServices listening on all interfaces (potential security risk):" >> "$REPORT_FILE"
            cat "$TEMP_DIR/network_analysis/all_interfaces.txt" >> "$REPORT_FILE"
            threats_found=$((threats_found + 1))
        fi
        
        # Check for unusual outbound connections
        grep "ESTAB" "$TEMP_DIR/network_analysis/connections.txt" | \
        grep -v -E "127.0.0.1|::1" > "$TEMP_DIR/network_analysis/established.txt"
        
        echo -e "\nEstablished connections to external hosts:" >> "$REPORT_FILE"
        cat "$TEMP_DIR/network_analysis/established.txt" >> "$REPORT_FILE"
        
        # Check for suspicious ports in current connections
        local suspicious_port_found=false
        for port in "${suspicious_ports[@]}"; do
            if grep -q ":$port " "$TEMP_DIR/network_analysis/connections.txt"; then
                log_warning "Suspicious port in active connections: $port"
                echo -e "\nSUSPICIOUS PORT IN ACTIVE CONNECTIONS: $port" >> "$REPORT_FILE"
                grep ":$port " "$TEMP_DIR/network_analysis/connections.txt" >> "$REPORT_FILE"
                suspicious_port_found=true
                threats_found=$((threats_found + 1))
            fi
        done
    fi
    
    # 3. DNS analysis
    log_info "Analyzing DNS traffic and configurations..."
    echo -e "\n### DNS Analysis" >> "$REPORT_FILE"
    
    # Check /etc/hosts file for suspicious entries
    if [[ -f "/etc/hosts" ]]; then
        cp "/etc/hosts" "$TEMP_DIR/network_analysis/hosts"
        grep -v -E "^#|localhost|ip6|broadcasthost" "$TEMP_DIR/network_analysis/hosts" > "$TEMP_DIR/network_analysis/custom_hosts.txt"
        
        if [[ -s "$TEMP_DIR/network_analysis/custom_hosts.txt" ]]; then
            log_warning "Found custom entries in /etc/hosts file"
            echo -e "Custom entries in /etc/hosts file:" >> "$REPORT_FILE"
            cat "$TEMP_DIR/network_analysis/custom_hosts.txt" >> "$REPORT_FILE"
            
            # Look for suspicious domains in hosts file
            grep -E "google|facebook|microsoft|apple|amazon|github" "$TEMP_DIR/network_analysis/custom_hosts.txt" > "$TEMP_DIR/network_analysis/suspicious_hosts.txt"
            
            if [[ -s "$TEMP_DIR/network_analysis/suspicious_hosts.txt" ]]; then
                log_warning "Suspicious entries for major domains found in /etc/hosts"
                echo -e "\nSUSPICIOUS HOST ENTRIES (potential DNS hijacking):" >> "$REPORT_FILE"
                cat "$TEMP_DIR/network_analysis/suspicious_hosts.txt" >> "$REPORT_FILE"
                threats_found=$((threats_found + 1))
            fi
        else
            log_success "No suspicious entries found in /etc/hosts"
            echo -e "No suspicious entries found in /etc/hosts" >> "$REPORT_FILE"
        fi
    fi
    
    # Check DNS resolvers
    if [[ -f "/etc/resolv.conf" ]]; then
        cp "/etc/resolv.conf" "$TEMP_DIR/network_analysis/resolv.conf"
        grep "nameserver" "$TEMP_DIR/network_analysis/resolv.conf" > "$TEMP_DIR/network_analysis/nameservers.txt"
        
        echo -e "\nConfigured DNS servers:" >> "$REPORT_FILE"
        cat "$TEMP_DIR/network_analysis/nameservers.txt" >> "$REPORT_FILE"
        
        # Check for non-standard DNS servers
        if ! grep -q -E "8.8.8.8|8.8.4.4|1.1.1.1|9.9.9.9|208.67.222.222|208.67.220.220|127.0.0.1" "$TEMP_DIR/network_analysis/nameservers.txt"; then
            log_warning "Non-standard DNS servers configured"
            echo -e "WARNING: Non-standard DNS servers are configured" >> "$REPORT_FILE"
            threats_found=$((threats_found + 1))
        fi
    fi
    
    # 4. Check firewall status
    log_info "Checking firewall configuration..."
    echo -e "\n### Firewall Analysis" >> "$REPORT_FILE"
    
    if command -v iptables &>/dev/null; then
        iptables -L -v -n > "$TEMP_DIR/network_analysis/iptables.txt"
        
        # Check if firewall is enabled
        if grep -q "Chain .* \(policy ACCEPT" "$TEMP_DIR/network_analysis/iptables.txt"; then
            log_warning "Firewall chains with ACCEPT policy detected"
            echo -e "WARNING: Firewall chains with default ACCEPT policy:" >> "$REPORT_FILE"
            grep "Chain .* \(policy ACCEPT" "$TEMP_DIR/network_analysis/iptables.txt" >> "$REPORT_FILE"
            threats_found=$((threats_found + 1))
        fi
        
        # Count rules
        local rule_count=$(grep -v "^Chain" "$TEMP_DIR/network_analysis/iptables.txt" | grep -v "^target" | grep -c "")
        
        echo -e "Firewall has $rule_count rules configured" >> "$REPORT_FILE"
        
        if [[ $rule_count -eq 0 ]]; then
            log_warning "No firewall rules detected"
            echo -e "WARNING: No firewall rules are configured" >> "$REPORT_FILE"
            threats_found=$((threats_found + 1))
        else
            echo -e "\nFirewall configuration:" >> "$REPORT_FILE"
            cat "$TEMP_DIR/network_analysis/iptables.txt" >> "$REPORT_FILE"
        fi
    elif command -v ufw &>/dev/null; then
        ufw status verbose > "$TEMP_DIR/network_analysis/ufw.txt"
        
        if grep -q "Status: inactive" "$TEMP_DIR/network_analysis/ufw.txt"; then
            log_warning "UFW firewall is inactive"
            echo -e "WARNING: UFW firewall is not enabled" >> "$REPORT_FILE"
            threats_found=$((threats_found + 1))
        else
            echo -e "UFW firewall is active with the following rules:" >> "$REPORT_FILE"
            cat "$TEMP_DIR/network_analysis/ufw.txt" >> "$REPORT_FILE"
        fi
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --list-all > "$TEMP_DIR/network_analysis/firewalld.txt"
        
        if ! grep -q "default: " "$TEMP_DIR/network_analysis/firewalld.txt"; then
            log_warning "FirewallD appears to be inactive"
            echo -e "WARNING: FirewallD appears to be inactive" >> "$REPORT_FILE"
            threats_found=$((threats_found + 1))
        else
            echo -e "FirewallD configuration:" >> "$REPORT_FILE"
            cat "$TEMP_DIR/network_analysis/firewalld.txt" >> "$REPORT_FILE"
        fi
    else
        log_warning "No firewall management tools found"
        echo -e "WARNING: No firewall management tools detected" >> "$REPORT_FILE"
        threats_found=$((threats_found + 1))
    fi
    
    # Report summary
    echo -e "\n### Network Analysis Summary" >> "$REPORT_FILE"
    if [[ $threats_found -gt 0 ]]; then
        log_warning "Network analysis complete. Found $threats_found suspicious indicators."
        echo -e "Total suspicious indicators found: $threats_found\nRecommendation: Review the detailed findings and consider implementing enhanced network controls." >> "$REPORT_FILE"
    else
        log_success "Network analysis complete. No suspicious indicators found."
        echo -e "No suspicious network indicators found.\nRecommendation: Continue with regular security monitoring." >> "$REPORT_FILE"
    fi
    
    return $threats_found
}

#===========================================
# 4. Container Security Analysis Functions
#===========================================
function container_security() {
    print_section_header "CONTAINER SECURITY ANALYSIS"
    
    log_info "Starting container security analysis..."
    local threats_found=0
    
    # Create container analysis directory
    mkdir -p "$TEMP_DIR/container_analysis"
    
    echo -e "## Container Security Analysis Results" >> "$REPORT_FILE"
    
    # Check if Docker is installed
    if ! command -v "$DOCKER_PATH" &>/dev/null; then
        log_warning "Docker not found. Container security analysis skipped."
        echo -e "Docker not found. Container security analysis skipped." >> "$REPORT_FILE"
        return 0
    fi
    
    # Check if Docker daemon is running
    if ! "$DOCKER_PATH" info &>/dev/null; then
        log_warning "Docker daemon is not running. Container security analysis limited."
        echo -e "Docker daemon is not running. Container security analysis limited." >> "$REPORT_FILE"
        
        # Check Docker socket permissions even if daemon is not running
        if [[ -S "/var/run/docker.sock" ]]; then
            ls -la "/var/run/docker.sock" > "$TEMP_DIR/container_analysis/docker_socket_perms.txt"
            echo -e "\n### Docker Socket Permissions" >> "$REPORT_FILE"
            cat "$TEMP_DIR/container_analysis/docker_socket_perms.txt" >> "$REPORT_FILE"
            
            # Check if socket permissions are too permissive
            if grep -q "srw-rw" "$TEMP_DIR/container_analysis/docker_socket_perms.txt"; then
                log_warning "Docker socket has too permissive permissions"
                echo -e "WARNING: Docker socket has too permissive permissions. This can lead to privilege escalation." >> "$REPORT_FILE"
                threats_found=$((threats_found + 1))
            fi
        fi
        
        # Check Docker configuration files for vulnerabilities
        echo -e "\n### Docker Configuration Analysis" >> "$REPORT_FILE"
        
        if [[ -f "/etc/docker/daemon.json" ]]; then
            cp "/etc/docker/daemon.json" "$TEMP_DIR/container_analysis/daemon.json"
            
            # Check for insecure configuration
            if grep -q "\"insecure-registries\"" "$TEMP_DIR/container_analysis/daemon.json"; then
                log_warning "Docker is configured to use insecure registries"
                echo -e "WARNING: Docker is configured to use insecure registries. This can lead to MITM attacks." >> "$REPORT_FILE"
                grep -A 5 "\"insecure-registries\"" "$TEMP_DIR/container_analysis/daemon.json" >> "$REPORT_FILE"
                threats_found=$((threats_found + 1))
            fi
            
            # Check for disabled security features
            if grep -q "\"disable-legacy-registry\": false" "$TEMP_DIR/container_analysis/daemon.json"; then
                log_warning "Legacy registry support is enabled"
                echo -e "WARNING: Legacy registry support is enabled, which may pose security risks." >> "$REPORT_FILE"
                threats_found=$((threats_found + 1))
            fi
            
            # Check if content trust is disabled
            if grep -q "\"content-trust\": false" "$TEMP_DIR/container_analysis/daemon.json"; then
                log_warning "Docker content trust is disabled"
                echo -e "WARNING: Docker content trust is disabled. Image signature verification not enforced." >> "$REPORT_FILE"
                threats_found=$((threats_found + 1))
            fi
        else
            log_info "No Docker daemon configuration file found at /etc/docker/daemon.json"
            echo -e "No Docker daemon configuration file found. Using default settings." >> "$REPORT_FILE"
        fi
        
        return $threats_found
    fi
    
    # Docker is running - perform full analysis
    log_info "Docker daemon is running. Performing comprehensive container security analysis..."
    
    # 1. Container Configuration Checks
    echo -e "\n### Container Configuration Checks" >> "$REPORT_FILE"
    
    # Get list of running containers
    "$DOCKER_PATH" ps -a > "$TEMP_DIR/container_analysis/containers.txt"
    local container_count=$(grep -c "" "$TEMP_DIR/container_analysis/containers.txt")
    local running_containers=$("$DOCKER_PATH" ps -q | wc -l)
    
    echo -e "Total containers: $container_count (Running: $running_containers)" >> "$REPORT_FILE"
    
    if [[ $running_containers -gt 0 ]]; then
        log_info "Analyzing running container configurations..."
        
        # Check containers running with privileged mode
        "$DOCKER_PATH" ps -a --format "{{.Names}}: {{.Command}}" | grep -i "privileged" > "$TEMP_DIR/container_analysis/privileged_containers.txt"
        if [[ -s "$TEMP_DIR/container_analysis/privileged_containers.txt" ]]; then
            local priv_count=$(grep -c "" "$TEMP_DIR/container_analysis/privileged_containers.txt")
            log_warning "Found $priv_count containers running in privileged mode"
            echo -e "\nWARNING: The following containers are running in privileged mode:" >> "$REPORT_FILE"
            cat "$TEMP_DIR/container_analysis/privileged_containers.txt" >> "$REPORT_FILE"
            echo -e "Privileged containers have full access to the host, including all devices." >> "$REPORT_FILE"
            threats_found=$((threats_found + 1))
        fi
        
        # Inspect each running container for security issues
        for container_id in $("$DOCKER_PATH" ps -q); do
            "$DOCKER_PATH" inspect "$container_id" > "$TEMP_DIR/container_analysis/container_${container_id}.json"
            
            # Get container name
            local container_name=$("$DOCKER_PATH" inspect --format '{{.Name}}' "$container_id" | sed 's/\///')
            
            # Check for security relevant mount points
            if grep -q "\"Source\": \"/var/run/docker.sock\"" "$TEMP_DIR/container_analysis/container_${container_id}.json"; then
                log_warning "Container $container_name has docker.sock mounted"
                echo -e "\nWARNING: Container $container_name has the Docker socket mounted." >> "$REPORT_FILE"
                echo -e "This allows the container to control the Docker host and escape container isolation." >> "$REPORT_FILE"
                threats_found=$((threats_found + 1))
            fi
            
            # Check for root user
            if ! grep -q "\"User\": \"[1-9]" "$TEMP_DIR/container_analysis/container_${container_id}.json"; then
                log_warning "Container $container_name is running as root"
                echo -e "\nWARNING: Container $container_name is running as root." >> "$REPORT_FILE"
                echo -e "This increases the risk of container escape if the container is compromised." >> "$REPORT_FILE"
                threats_found=$((threats_found + 1))
            fi
            
            # Check for AppArmor/SELinux
            if grep -q "\"AppArmorProfile\": \"\"" "$TEMP_DIR/container_analysis/container_${container_id}.json" && \
               grep -q "\"SelinuxLabel\": \"\"" "$TEMP_DIR/container_analysis/container_${container_id}.json"; then
                log_warning "Container $container_name has no AppArmor or SELinux profiles"
                echo -e "\nWARNING: Container $container_name has no AppArmor or SELinux profiles." >> "$REPORT_FILE"
                echo -e "This reduces container isolation. Consider using security profiles." >> "$REPORT_FILE"
                threats_found=$((threats_found + 1))
            fi
            
            # Check for NET_ADMIN, SYS_ADMIN capabilities
            if grep -q "\"CapAdd\".*\"NET_ADMIN\"" "$TEMP_DIR/container_analysis/container_${container_id}.json" || \
               grep -q "\"CapAdd\".*\"SYS_ADMIN\"" "$TEMP_DIR/container_analysis/container_${container_id}.json"; then
                log_warning "Container $container_name has dangerous capabilities"
                echo -e "\nWARNING: Container $container_name has dangerous capabilities added (NET_ADMIN or SYS_ADMIN)." >> "$REPORT_FILE"
                echo -e "These capabilities may allow container escape vectors." >> "$REPORT_FILE"
                threats_found=$((threats_found + 1))
            fi
        done
    else
        log_info "No running containers found"
        echo -e "No running containers found." >> "$REPORT_FILE"
    fi
    
    # 2. Image Security Scanning
    echo -e "\n### Image Security Analysis" >> "$REPORT_FILE"
    
    # Get list of images
    "$DOCKER_PATH" images > "$TEMP_DIR/container_analysis/images.txt"
    local image_count=$(grep -c "" "$TEMP_DIR/container_analysis/images.txt")
    
    echo -e "Total images: $image_count" >> "$REPORT_FILE"
    
    if [[ $image_count -gt 0 ]]; then
        log_info "Analyzing Docker images..."
        
        # Check for images with no tag or latest tag only
        grep "latest" "$TEMP_DIR/container_analysis/images.txt" > "$TEMP_DIR/container_analysis/latest_images.txt"
        if [[ -s "$TEMP_DIR/container_analysis/latest_images.txt" ]]; then
            local latest_count=$(grep -c "" "$TEMP_DIR/container_analysis/latest_images.txt")
            log_warning "Found $latest_count images using 'latest' tag"
            echo -e "\nWARNING: The following images use the 'latest' tag, which makes it hard to track vulnerabilities:" >> "$REPORT_FILE"
            cat "$TEMP_DIR/container_analysis/latest_images.txt" >> "$REPORT_FILE"
            echo -e "Consider using specific version tags for better security tracking." >> "$REPORT_FILE"
            threats_found=$((threats_found + 1))
        fi
        
        # Check for base images with known vulnerabilities
        grep -E "alpine:3\.[0-8]|debian:(stretch|jessie)|ubuntu:(trusty|xenial)" "$TEMP_DIR/container_analysis/images.txt" > "$TEMP_DIR/container_analysis/outdated_images.txt"
        if [[ -s "$TEMP_DIR/container_analysis/outdated_images.txt" ]]; then
            log_warning "Found potentially outdated base images"
            echo -e "\nWARNING: The following images are based on potentially outdated distributions:" >> "$REPORT_FILE"
            cat "$TEMP_DIR/container_analysis/outdated_images.txt" >> "$REPORT_FILE"
            echo -e "These may contain known vulnerabilities. Consider updating to newer base images." >> "$REPORT_FILE"
            threats_found=$((threats_found + 1))
        fi
        
        # Analyze image history for sensitive commands
        for image_id in $("$DOCKER_PATH" images -q); do
            "$DOCKER_PATH" history --no-trunc "$image_id" > "$TEMP_DIR/container_analysis/history_${image_id}.txt"
            
            # Check for sensitive operations in image layers
            grep -E "curl|wget|apt-key|apt-add-repository|pip install|npm install --global|chmod 777" "$TEMP_DIR/container_analysis/history_${image_id}.txt" > "$TEMP_DIR/container_analysis/suspicious_commands_${image_id}.txt"
            
            if [[ -s "$TEMP_DIR/container_analysis/suspicious_commands_${image_id}.txt" ]]; then
                local image_name=$(docker inspect --format='{{.RepoTags}}' "$image_id" | tr -d '[]')
                log_warning "Found potentially risky commands in image $image_name"
                echo -e "\nWARNING: Potentially risky commands found in image $image_name:" >> "$REPORT_FILE"
                cat "$TEMP_DIR/container_analysis/suspicious_commands_${image_id}.txt" >> "$REPORT_FILE"
                echo -e "These commands may introduce security vulnerabilities or indicate unverified content." >> "$REPORT_FILE"
                threats_found=$((threats_found + 1))
            fi
            
            # Check for secrets in environment variables
            grep -E "ENV.*PASSWORD|ENV.*SECRET|ENV.*KEY|ENV.*TOKEN" "$TEMP_DIR/container_analysis/history_${image_id}.txt" > "$TEMP_DIR/container_analysis/secrets_${image_id}.txt"
            
            if [[ -s "$TEMP_DIR/container_analysis/secrets_${image_id}.txt" ]]; then
                local image_name=$(docker inspect --format='{{.RepoTags}}' "$image_id" | tr -d '[]')
                log_warning "Found potential secrets in image $image_name"
                echo -e "\nWARNING: Potential secrets found in image $image_name environment variables:" >> "$REPORT_FILE"
                cat "$TEMP_DIR/container_analysis/secrets_${image_id}.txt" >> "$REPORT_FILE"
                echo -e "Storing secrets in image layers is a significant security risk. Use Docker secrets or environment variables at runtime instead." >> "$REPORT_FILE"
                threats_found=$((threats_found + 1))
            fi
        done
        
        # Check for unsigned images
        echo -e "\n### Image Signature Verification" >> "$REPORT_FILE"
        
        if command -v notary &>/dev/null; then
            log_info "Checking image signatures with Notary..."
            for image in $("$DOCKER_PATH" images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>"); do
                if ! notary -s https://notary.docker.io verify "$image" &>/dev/null; then
                    log_warning "Image $image is not signed"
                    echo -e "WARNING: Image $image is not cryptographically signed." >> "$REPORT_FILE"
                    echo -e "Unsigned images cannot be verified for authenticity and may contain malicious code." >> "$REPORT_FILE"
                    threats_found=$((threats_found + 1))
                fi
            done
        else
            log_warning "Notary not available. Image signature verification skipped."
            echo -e "Notary tool not available. Image signature verification skipped." >> "$REPORT_FILE"
            echo -e "Consider installing Notary to verify image signatures." >> "$REPORT_FILE"
        fi
        
        # Scan images for vulnerabilities if a scanner is available
        echo -e "\n### Vulnerability Scanning" >> "$REPORT_FILE"
        
        if command -v trivy &>/dev/null; then
            log_info "Scanning images for vulnerabilities with Trivy..."
            
            for image in $("$DOCKER_PATH" images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>"); do
                log_info "Scanning image: $image"
                trivy image --no-progress --security-checks vuln "$image" > "$TEMP_DIR/container_analysis/trivy_${image//\//_}.txt"
                
                # Count high and critical vulnerabilities
                if [[ -s "$TEMP_DIR/container_analysis/trivy_${image//\//_}.txt" ]]; then
                    local critical_count=$(grep -c "CRITICAL" "$TEMP_DIR/container_analysis/trivy_${image//\//_}.txt")
                    local high_count=$(grep -c "HIGH" "$TEMP_DIR/container_analysis/trivy_${image//\//_}.txt")
                    
                    if [[ $critical_count -gt 0 || $high_count -gt 0 ]]; then
                        log_warning "Image $image has $critical_count critical and $high_count high vulnerabilities"
                        echo -e "\nVulnerabilities found in image $image:" >> "$REPORT_FILE"
                        echo -e "- Critical: $critical_count" >> "$REPORT_FILE"
                        echo -e "- High: $high_count" >> "$REPORT_FILE"
                        echo -e "\nTop 10 critical/high vulnerabilities:" >> "$REPORT_FILE"
                        grep -A 3 -E "CRITICAL|HIGH" "$TEMP_DIR/container_analysis/trivy_${image//\//_}.txt" | head -n 30 >> "$REPORT_FILE"
                        echo -e "\nRecommendation: Update this image to a patched version." >> "$REPORT_FILE"
                        threats_found=$((threats_found + threats_found + critical_count + high_count))
                    fi
                fi
            done
        elif command -v grype &>/dev/null; then
            log_info "Scanning images for vulnerabilities with Grype..."
            
            for image in $("$DOCKER_PATH" images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>"); do
                log_info "Scanning image: $image"
                grype "$image" -o json > "$TEMP_DIR/container_analysis/grype_${image//\//_}.json"
                
                # Extract critical and high vulnerabilities
                if [[ -s "$TEMP_DIR/container_analysis/grype_${image//\//_}.json" ]]; then
                    jq '.matches[] | select(.vulnerability.severity == "Critical" or .vulnerability.severity == "High")' "$TEMP_DIR/container_analysis/grype_${image//\//_}.json" > "$TEMP_DIR/container_analysis/grype_high_${image//\//_}.json"
                    
                    if [[ -s "$TEMP_DIR/container_analysis/grype_high_${image//\//_}.json" ]]; then
                        local vuln_count=$(grep -c "" "$TEMP_DIR/container_analysis/grype_high_${image//\//_}.json")
                        log_warning "Image $image has $vuln_count critical/high vulnerabilities"
                        echo -e "\nHigh/Critical vulnerabilities found in image $image: $vuln_count" >> "$REPORT_FILE"
                        echo -e "\nRecommendation: Update this image to a patched version." >> "$REPORT_FILE"
                        threats_found=$((threats_found + vuln_count))
                    fi
                fi
            done
        else
            log_warning "No vulnerability scanner found (trivy or grype). Image vulnerability scanning skipped."
            echo -e "No vulnerability scanner found. Consider installing Trivy or Grype for image scanning." >> "$REPORT_FILE"
        fi
    else
        log_info "No Docker images found"
        echo -e "No Docker images found." >> "$REPORT_FILE"
    fi
    
    # 3. Call runtime security check function
    runtime_security_check
    
    # Report summary
    echo -e "\n### Container Security Summary" >> "$REPORT_FILE"
    if [[ $threats_found -gt 0 ]]; then
        log_warning "Container security analysis complete. Found $threats_found security issues."
        echo -e "Total container security issues found: $threats_found\nRecommendation: Review the detailed findings and address container security concerns." >> "$REPORT_FILE"
    else
        log_success "Container security analysis complete. No security issues found."
        echo -e "No container security issues found.\nRecommendation: Continue following container security best practices." >> "$REPORT_FILE"
    fi
    
    return $threats_found
}

#===========================================
# 5. Container Runtime Security Check Function
#===========================================
function runtime_security_check() {
    echo -e "\n### Container Runtime Security Analysis" >> "$REPORT_FILE"
    log_info "Performing container runtime security analysis..."
    local runtime_threats=0
    
    # Check if Docker is running
    if ! "$DOCKER_PATH" ps &>/dev/null; then
        log_warning "Docker daemon is not running. Runtime analysis skipped."
        echo -e "Docker daemon is not running. Runtime analysis skipped." >> "$REPORT_FILE"
        return 0
    fi
    
    # Get running containers
    local running_containers=$("$DOCKER_PATH" ps -q)
    if [[ -z "$running_containers" ]]; then
        log_info "No running containers found. Runtime analysis skipped."
        echo -e "No running containers found. Runtime analysis skipped." >> "$REPORT_FILE"
        return 0
    fi
    
    log_info "Analyzing runtime security for $(echo "$running_containers" | wc -w) containers..."
    
    # 1. Check for containers running with sensitive mounts
    echo -e "\nContainers with sensitive host mounts:" >> "$REPORT_FILE"
    for container in $running_containers; do
        local container_name=$("$DOCKER_PATH" inspect --format='{{.Name}}' "$container" | sed 's/\///')
        
        # Check for sensitive mounts
        "$DOCKER_PATH" inspect --format='{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}:{{.Destination}} {{end}}{{end}}' "$container" > "$TEMP_DIR/container_analysis/mounts_${container}.txt"
        
        grep -E "/etc|/var|/sys|/proc|/dev|/home|/root" "$TEMP_DIR/container_analysis/mounts_${container}.txt" > "$TEMP_DIR/container_analysis/sensitive_mounts_${container}.txt"
        
        if [[ -s "$TEMP_DIR/container_analysis/sensitive_mounts_${container}.txt" ]]; then
            log_warning "Container $container_name has sensitive host mounts"
            echo -e "\nContainer $container_name has sensitive host mounts:" >> "$REPORT_FILE"
            cat "$TEMP_DIR/container_analysis/sensitive_mounts_${container}.txt" >> "$REPORT_FILE"
            echo -e "Risk: These mounts may allow container escape or host modification." >> "$REPORT_FILE"
            echo -e "Recommendation: Remove unnecessary host mounts and use volumes instead." >> "$REPORT_FILE"
            runtime_threats=$((runtime_threats + 1))
        fi
    done
    
    # 2. Check for containers with excessive capabilities
    echo -e "\nContainers with excessive capabilities:" >> "$REPORT_FILE"
    for container in $running_containers; do
        local container_name=$("$DOCKER_PATH" inspect --format='{{.Name}}' "$container" | sed 's/\///')
        
        # Check capabilities
        "$DOCKER_PATH" inspect --format='{{range .HostConfig.CapAdd}}{{.}} {{end}}' "$container" > "$TEMP_DIR/container_analysis/caps_${container}.txt"
        
        if grep -q "SYS_ADMIN\|NET_ADMIN\|ALL" "$TEMP_DIR/container_analysis/caps_${container}.txt"; then
            log_warning "Container $container_name has excessive capabilities"
            echo -e "\nContainer $container_name has excessive capabilities:" >> "$REPORT_FILE"
            cat "$TEMP_DIR/container_analysis/caps_${container}.txt" >> "$REPORT_FILE"
            echo -e "Risk: These capabilities may allow container escape vectors." >> "$REPORT_FILE"
            echo -e "Recommendation: Remove unnecessary capabilities and run with least privileges." >> "$REPORT_FILE"
            runtime_threats=$((runtime_threats + 1))
        fi
    done
    
    # 3. Check for containers running with host network
    echo -e "\nContainers using host network:" >> "$REPORT_FILE"
    for container in $running_containers; do
        local container_name=$("$DOCKER_PATH" inspect --format='{{.Name}}' "$container" | sed 's/\///')
        
        # Check for host network
        local network_mode=$("$DOCKER_PATH" inspect --format='{{.HostConfig.NetworkMode}}' "$container")
        
        if [[ "$network_mode" == "host" ]]; then
            log_warning "Container $container_name is using host network"
            echo -e "\nContainer $container_name is using host network" >> "$REPORT_FILE"
            echo -e "Risk: Container has full access to host networking and can bind to privileged ports." >> "$REPORT_FILE"
            echo -e "Recommendation: Use bridge networking with exposed ports instead." >> "$REPORT_FILE"
            runtime_threats=$((runtime_threats + 1))
        fi
    done
    
    # 4. Check for containers without resource limits
    echo -e "\nContainers without resource limits:" >> "$REPORT_FILE"
    for container in $running_containers; do
        local container_name=$("$DOCKER_PATH" inspect --format='{{.Name}}' "$container" | sed 's/\///')
        
        # Check for memory limits
        local memory_limit=$("$DOCKER_PATH" inspect --format='{{.HostConfig.Memory}}' "$container")
        local cpu_limit=$("$DOCKER_PATH" inspect --format='{{.HostConfig.NanoCpus}}' "$container")
        
        if [[ "$memory_limit" == "0" && "$cpu_limit" == "0" ]]; then
            log_warning "Container $container_name has no resource limits"
            echo -e "\nContainer $container_name has no CPU or memory limits" >> "$REPORT_FILE"
            echo -e "Risk: Container could consume all host resources, leading to denial of service." >> "$REPORT_FILE"
            echo -e "Recommendation: Add --memory and --cpu-quota limits to container." >> "$REPORT_FILE"
            runtime_threats=$((runtime_threats + 1))
        fi
    done
    
    # 5. Check for containers running outdated software
    echo -e "\nAnalyzing container processes for outdated software:" >> "$REPORT_FILE"
    for container in $running_containers; do
        local container_name=$("$DOCKER_PATH" inspect --format='{{.Name}}' "$container" | sed 's/\///')
        
        # Try to get package listings from container
        "$DOCKER_PATH" exec "$container" sh -c "command -v dpkg >/dev/null && dpkg -l || command -v rpm >/dev/null && rpm -qa || command -v apk >/dev/null && apk info -v" 2>/dev/null > "$TEMP_DIR/container_analysis/packages_${container}.txt"
        
        if [[ -s "$TEMP_DIR/container_analysis/packages_${container}.txt" ]]; then
            # Check for common outdated packages
            grep -E "openssl|openssh|apache2|nginx|php|python|bash|kernel|lib(ssl|crypto)" "$TEMP_DIR/container_analysis/packages_${container}.txt" > "$TEMP_DIR/container_analysis/critical_packages_${container}.txt"
            
            if [[ -s "$TEMP_DIR/container_analysis/critical_packages_${container}.txt" ]]; then
                echo -e "\nContainer $container_name critical packages:" >> "$REPORT_FILE"
                cat "$TEMP_DIR/container_analysis/critical_packages_${container}.txt" >> "$REPORT_FILE"
                
                # Check for OpenSSL versions with known CVEs
                if grep -q -E "openssl.*1\.0\.[0-1]|openssl.*0\.9\.|openssl.*1\.1\.0[a-z]" "$TEMP_DIR/container_analysis/critical_packages_${container}.txt"; then
                    log_warning "Container $container_name contains outdated OpenSSL version with known vulnerabilities"
                    echo -e "VULNERABILITY: Container $container_name has outdated OpenSSL with known vulnerabilities" >> "$REPORT_FILE"
                    echo -e "Recommendation: Update OpenSSL package immediately" >> "$REPORT_FILE"
                    runtime_threats=$((runtime_threats + 1))
                fi
                
                # Check for outdated SSH versions
                if grep -q -E "openssh.*7\.[0-7]|openssh.*6\.|openssh.*5\." "$TEMP_DIR/container_analysis/critical_packages_${container}.txt"; then
                    log_warning "Container $container_name contains outdated SSH version with known vulnerabilities"
                    echo -e "VULNERABILITY: Container $container_name has outdated SSH with known vulnerabilities" >> "$REPORT_FILE"
                    echo -e "Recommendation: Update SSH package immediately" >> "$REPORT_FILE"
                    runtime_threats=$((runtime_threats + 1))
                fi
                
                # Check for outdated web servers
                if grep -q -E "nginx.*1\.[0-9]\.|apache2.*2\.2\.|apache2.*2\.4\.[0-9]$|apache2.*2\.4\.1[0-9]$" "$TEMP_DIR/container_analysis/critical_packages_${container}.txt"; then
                    log_warning "Container $container_name contains potentially outdated web server"
                    echo -e "VULNERABILITY: Container $container_name has potentially outdated web server" >> "$REPORT_FILE"
                    echo -e "Recommendation: Update web server packages" >> "$REPORT_FILE"
                    runtime_threats=$((runtime_threats + 1))
                fi
            fi
        fi
    done
    
    # 6. Analyze container network isolation
    echo -e "\nContainer network isolation analysis:" >> "$REPORT_FILE"
    for container in $running_containers; do
        local container_name=$("$DOCKER_PATH" inspect --format='{{.Name}}' "$container" | sed 's/\///')
        
        # Check if container is connected to host network or has port exposure
        local network_mode=$("$DOCKER_PATH" inspect --format='{{.HostConfig.NetworkMode}}' "$container")
        local published_ports=$("$DOCKER_PATH" inspect --format='{{range $p, $conf := .NetworkSettings.Ports}}{{$p}} -> {{(index $conf 0).HostPort}}{{"\n"}}{{end}}' "$container")
        
        if [[ "$network_mode" != "host" && -z "$published_ports" ]]; then
            log_success "Container $container_name has good network isolation"
            echo -e "\nContainer $container_name has good network isolation" >> "$REPORT_FILE"
        else
            echo -e "\nContainer $container_name network exposure:" >> "$REPORT_FILE"
            if [[ "$network_mode" == "host" ]]; then
                echo -e "- Using host network (no isolation)" >> "$REPORT_FILE"
            else
                echo -e "Exposed ports:" >> "$REPORT_FILE"
                echo -e "$published_ports" >> "$REPORT_FILE"
                
                # Check for dangerous exposed ports
                if echo "$published_ports" | grep -q -E "22/|23/|3389/|5900/|3306/|1433/|5432/|27017/|6379/"; then
                    log_warning "Container $container_name exposes sensitive service ports"
                    echo -e "WARNING: Container exposes sensitive service ports that should typically be restricted" >> "$REPORT_FILE"
                    runtime_threats=$((runtime_threats + 1))
                fi
            fi
        fi
    done
    
    # 7. Check for containers running as privileged or with potentially malicious processes
    echo -e "\nContainer process analysis:" >> "$REPORT_FILE"
    for container in $running_containers; do
        local container_name=$("$DOCKER_PATH" inspect --format='{{.Name}}' "$container" | sed 's/\///')
        
        # Get process list from container
        "$DOCKER_PATH" exec "$container" ps -ef > "$TEMP_DIR/container_analysis/processes_${container}.txt" 2>/dev/null
        
        if [[ -s "$TEMP_DIR/container_analysis/processes_${container}.txt" ]]; then
            # Check for suspicious processes running in the container
            grep -E "nc |netcat|wget|curl|bash -i|telnet|nmap|ssh-keygen|dd if=|mkfifo|socat" "$TEMP_DIR/container_analysis/processes_${container}.txt" > "$TEMP_DIR/container_analysis/suspicious_processes_${container}.txt"
            
            if [[ -s "$TEMP_DIR/container_analysis/suspicious_processes_${container}.txt" ]]; then
                log_warning "Container $container_name is running suspicious processes"
                echo -e "\nWARNING: Container $container_name is running suspicious processes:" >> "$REPORT_FILE"
                cat "$TEMP_DIR/container_analysis/suspicious_processes_${container}.txt" >> "$REPORT_FILE"
                echo -e "Recommendation: Investigate these processes for potential compromise" >> "$REPORT_FILE"
                runtime_threats=$((runtime_threats + 2))
            fi
        fi
    done
    
    # Report runtime analysis summary
    if [[ $runtime_threats -gt 0 ]]; then
        log_warning "Container runtime analysis complete. Found $runtime_threats security issues."
        echo -e "\nContainer runtime analysis summary: Found $runtime_threats security issues" >> "$REPORT_FILE"
        echo -e "Recommendation: Review container security configurations and apply the principle of least privilege" >> "$REPORT_FILE"
    else
        log_success "Container runtime analysis complete. No security issues found."
        echo -e "\nContainer runtime analysis summary: No security issues found" >> "$REPORT_FILE"
        echo -e "Recommendation: Continue to monitor container runtime security regularly" >> "$REPORT_FILE"
    fi
    
    return $runtime_threats
}

#===========================================
# Report Generation with Security Scoring
#===========================================
function generate_final_report() {
    print_section_header "SECURITY ASSESSMENT REPORT"
    
    local total_score=100
    local memory_score=0
    local rootkit_score=0
    local network_score=0
    local container_score=0
    local critical_issues=0
    local high_issues=0
    local medium_issues=0
    local low_issues=0
    
    echo -e "\n## SYSTEM SECURITY ASSESSMENT SCORE" >> "$REPORT_FILE"
    
    # Extract threat counts from analysis results
    if grep -q "Memory analysis complete. Found .* suspicious indicators" "$REPORT_FILE"; then
        memory_score=$(grep "Memory analysis complete. Found .* suspicious indicators" "$REPORT_FILE" | grep -o "[0-9]\+" | head -1)
        if [[ $memory_score -gt 5 ]]; then
            critical_issues=$((critical_issues + 1))
            total_score=$((total_score - 20))
        elif [[ $memory_score -gt 0 ]]; then
            high_issues=$((high_issues + 1))
            total_score=$((total_score - 10))
        fi
    fi
    
    if grep -q "Rootkit detection complete. Found .* suspicious indicators" "$REPORT_FILE"; then
        rootkit_score=$(grep "Rootkit detection complete. Found .* suspicious indicators" "$REPORT_FILE" | grep -o "[0-9]\+" | head -1)
        if [[ $rootkit_score -gt 0 ]]; then
            critical_issues=$((critical_issues + rootkit_score))
            total_score=$((total_score - (rootkit_score * 10)))
        fi
    fi
    
    if grep -q "Network analysis complete. Found .* suspicious indicators" "$REPORT_FILE"; then
        network_score=$(grep "Network analysis complete. Found .* suspicious indicators" "$REPORT_FILE" | grep -o "[0-9]\+" | head -1)
        if [[ $network_score -gt 3 ]]; then
            high_issues=$((high_issues + 1))
            total_score=$((total_score - 15))
        elif [[ $network_score -gt 0 ]]; then
            medium_issues=$((medium_issues + 1))
            total_score=$((total_score - 5))
        fi
    fi
    
    if grep -q "Container security analysis complete. Found .* security issues" "$REPORT_FILE"; then
        container_score=$(grep "Container security analysis complete. Found .* security issues" "$REPORT_FILE" | grep -o "[0-9]\+" | head -1)
        if [[ $container_score -gt 5 ]]; then
            high_issues=$((high_issues + 1))
            total_score=$((total_score - 15))
        elif [[ $container_score -gt 0 ]]; then
            medium_issues=$((medium_issues + 1))
            total_score=$((total_score - 5))
        fi
    fi
    
    # Count warnings and errors
    local warning_count=$(grep -c "\[WARNING\]" "$LOG_FILE")
    local error_count=$(grep -c "\[ERROR\]" "$LOG_FILE")
    
    # Add warnings and errors to issue counts
    if [[ $error_count -gt 0 ]]; then
        high_issues=$((high_issues + 1))
    fi
    
    if [[ $warning_count -gt 10 ]]; then
        medium_issues=$((medium_issues + 1))
    elif [[ $warning_count -gt 0 ]]; then
        low_issues=$((low_issues + 1))
    fi
    
    # Ensure the score doesn't go below 0
    if [[ $total_score -lt 0 ]]; then
        total_score=0
    fi
    
    # Calculate risk level
    local risk_level="Low"
    local risk_color=$GREEN
    
    if [[ $total_score -lt 60 || $critical_issues -gt 0 ]]; then
        risk_level="Critical"
        risk_color=$RED
    elif [[ $total_score -lt 80 || $high_issues -gt 0 ]]; then
        risk_level="High"
        risk_color=$RED
    elif [[ $total_score -lt 90 || $medium_issues -gt 0 ]]; then
        risk_level="Medium"
        risk_color=$YELLOW
    fi
    
    # Format the report
    local date_time=$(date "+%Y-%m-%d %H:%M:%S")
    local hostname=$(hostname)
    local kernel=$(uname -r)
    local os_info=$(grep -E "^(NAME|VERSION)=" /etc/os-release | tr '\n' ' ' 2>/dev/null || echo "OS information not available")
    
    # Print summary to console
    echo -e "${BOLD}${BLUE}===============================================${NC}"
    echo -e "${BOLD}${BLUE}           SECURITY ASSESSMENT RESULTS           ${NC}"
    echo -e "${BOLD}${BLUE}===============================================${NC}"
    echo -e "${BOLD}Host:${NC} $hostname"
    echo -e "${BOLD}Date:${NC} $date_time"
    echo -e "${BOLD}OS:${NC} $os_info"
    echo -e "${BOLD}Kernel:${NC} $kernel"
    echo -e "${BOLD}${BLUE}-----------------------------------------------${NC}"
    echo -e "${BOLD}Security Score:${NC} ${BOLD}${risk_color}$total_score/100${NC}"
    echo -e "${BOLD}Risk Level:${NC} ${BOLD}${risk_color}$risk_level${NC}"
    echo -e "${BOLD}Issue Summary:${NC}"
    echo -e "  Critical Issues: ${RED}$critical_issues${NC}"
    echo -e "  High Issues: ${RED}$high_issues${NC}"
    echo -e "  Medium Issues: ${YELLOW}$medium_issues${NC}"
    echo -e "  Low Issues: ${GREEN}$low_issues${NC}"
    echo -e "${BOLD}${BLUE}-----------------------------------------------${NC}"
    echo -e "Detailed report saved to: ${BOLD}$REPORT_FILE${NC}"
    echo -e "${BOLD}${BLUE}===============================================${NC}\n"
    
    # Add summary to report file
    echo -e "==================================================" >> "$REPORT_FILE"
    echo -e "                EXECUTIVE SUMMARY                  " >> "$REPORT_FILE"
    echo -e "==================================================" >> "$REPORT_FILE"
    echo -e "Security Assessment Score: $total_score/100" >> "$REPORT_FILE"
    echo -e "Risk Level: $risk_level\n" >> "$REPORT_FILE"
    echo -e "System Information:" >> "$REPORT_FILE"
    echo -e "  Host: $hostname" >> "$REPORT_FILE"
    echo -e "  Date: $date_time" >> "$REPORT_FILE"
    echo -e "  OS: $os_info" >> "$REPORT_FILE"
    echo -e "  Kernel: $kernel\n" >> "$REPORT_FILE"
    
    echo -e "Issue Summary:" >> "$REPORT_FILE"
    echo -e "  Critical Issues: $critical_issues" >> "$REPORT_FILE"
    echo -e "  High Issues: $high_issues" >> "$REPORT_FILE"
    echo -e "  Medium Issues: $medium_issues" >> "$REPORT_FILE"
    echo -e "  Low Issues: $low_issues\n" >> "$REPORT_FILE"
    
    # Add specific findings summary
    echo -e "Key Findings:" >> "$REPORT_FILE"
    
    if [[ $memory_score -gt 0 ]]; then
        echo -e "  [!] Memory analysis found $memory_score suspicious indicators" >> "$REPORT_FILE"
    else
        echo -e "  [✓] Memory analysis found no suspicious indicators" >> "$REPORT_FILE"
    fi
    
    if [[ $rootkit_score -gt 0 ]]; then
        echo -e "  [!] Rootkit detection found $rootkit_score suspicious indicators" >> "$REPORT_FILE"
    else
        echo -e "  [✓] No rootkit indicators detected" >> "$REPORT_FILE"
    fi
    
    if [[ $network_score -gt 0 ]]; then
        echo -e "  [!] Network analysis found $network_score suspicious indicators" >> "$REPORT_FILE"
    else
        echo -e "  [✓] Network analysis found no suspicious indicators" >> "$REPORT_FILE"
    fi
    
    if [[ $container_score -gt 0 ]]; then
        echo -e "  [!] Container security analysis found $container_score issues" >> "$REPORT_FILE"
    else
        echo -e "  [✓] Container security analysis found no issues" >> "$REPORT_FILE"
    fi
    
    # Add top recommendations
    echo -e "\nTop Recommendations:" >> "$REPORT_FILE"
    
    # Extract top warnings from log file
    grep "\[WARNING\]" "$LOG_FILE" | head -10 | sed 's/\[WARNING\]/  -/g' >> "$REPORT_FILE"
    
    if [[ $critical_issues -gt 0 || $high_issues -gt 0 ]]; then
        echo -e "\nCRITICAL: Immediate remediation recommended!" >> "$REPORT_FILE"
    elif [[ $medium_issues -gt 0 ]]; then
        echo -e "\nWARNING: Remediation recommended in the near term." >> "$REPORT_FILE"
    else
        echo -e "\nINFO: System appears secure. Maintain regular security monitoring." >> "$REPORT_FILE"
    fi
    
    echo -e "\n==================================================" >> "$REPORT_FILE"
    echo -e "         End of Security Assessment Report         " >> "$REPORT_FILE"
    echo -e "==================================================\n" >> "$REPORT_FILE"
    
    # Return overall risk level as exit code (0=low, 1=medium, 2=high, 3=critical)
    if [[ $critical_issues -gt 0 ]]; then
        return 3
    elif [[ $high_issues -gt 0 ]]; then
        return 2
    elif [[ $medium_issues -gt 0 ]]; then
        return 1
    else
        return 0
    fi
}

#===========================================
# Signal and Error Handling
#===========================================

# Cleanup function for proper exit
function cleanup_and_exit() {
    local exit_code=$1
    
    # Only cleanup if we're not in debug mode
    if [[ $DEBUG_MODE == false ]]; then
        cleanup
    else
        echo -e "${YELLOW}Debug mode enabled - temporary files preserved at: $TEMP_DIR${NC}"
    fi
    
    if [[ -n "$REPORT_FILE" && -f "$REPORT_FILE" ]]; then
        echo -e "${GREEN}Report saved to: $REPORT_FILE${NC}"
    fi
    
    # Exit with provided code or default to 0
    exit ${exit_code:-0}
}

# Handle signals
function handle_sigint() {
    echo -e "\n${YELLOW}Analysis interrupted by user.${NC}"
    cleanup_and_exit 130
}

function handle_sigterm() {
    echo -e "\n${YELLOW}Analysis terminated.${NC}"
    cleanup_and_exit 143
}

function handle_exit() {
    # Only run cleanup on normal exit if not already handled
    if [[ $? -eq 0 ]]; then
        cleanup_and_exit 0
    fi
}

# Set up signal traps
function setup_traps() {
    trap handle_sigint SIGINT
    trap handle_sigterm SIGTERM
    trap handle_exit EXIT
}

#===========================================
# Help and Documentation
#===========================================

# Progress indicator function
function show_progress() {
    local pid=$1
    local delay=0.5
    local spinstr='|/-\'
    
    while ps -p $pid > /dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

function display_help() {
    echo -e "${BOLD}${BLUE}Advanced Security Analyzer${NC}"
    echo -e "A comprehensive security analysis tool for Linux systems\n"
    
    echo -e "${BOLD}USAGE:${NC}"
    echo -e "  $0 [OPTIONS]\n"
    
    echo -e "${BOLD}OPTIONS:${NC}"
    echo -e "  ${BOLD}-a, --all${NC}             Run all security checks"
    echo -e "  ${BOLD}-m, --memory${NC}          Perform memory forensics analysis"
    echo -e "  ${BOLD}-r, --rootkit${NC}         Perform rootkit detection"
    echo -e "  ${BOLD}-n, --network${NC}         Perform network traffic analysis"
    echo -e "  ${BOLD}-c, --container${NC}       Perform container security analysis"
    echo -e "  ${BOLD}-d, --malware${NC}         Perform malware detection"
    echo -e "  ${BOLD}-t, --time TIME${NC}       Set network capture duration (seconds, default: 60)"
    echo -e "  ${BOLD}-o, --output FILE${NC}     Specify output report file"
    echo -e "  ${BOLD}-q, --quiet${NC}           Minimal output"
    echo -e "  ${BOLD}--debug${NC}               Enable debug mode (preserves temp files)"
    echo -e "  ${BOLD}-h, --help${NC}            Display this help message\n"
    
    echo -e "${BOLD}EXAMPLES:${NC}"
    echo -e "  Run a full system security analysis:"
    echo -e "    $0 --all\n"
    
    echo -e "  Run network and rootkit detection only:"
    echo -e "    $0 --network --rootkit\n"
    
    echo -e "  Run container security analysis with custom report name:"
    echo -e "    $0 --container --output container_security_report.txt\n"
    
    echo -e "${BOLD}NOTES:${NC}"
    echo -e "  - This script must be run as root"
    echo -e "  - For comprehensive analysis, install all dependencies:"
    echo -e "    volatility, tcpdump, yara, docker, lsof, strings, objdump\n"
    
    echo -e "${BOLD}AUTHOR:${NC}"
    echo -e "  Advanced Security Analyzer - Comprehensive security assessment tool"
    echo -e "  Version: 1.0.0\n"
}

#===========================================
# Main Program
#===========================================

# Status and error message function
function show_status() {
    local message=$1
    local status=$2  # 0=success, 1=warning, 2=error
    
    case $status in
        0) echo -e "${GREEN}[✓] $message${NC}" ;;
        1) echo -e "${YELLOW}[!] $message${NC}" ;;
        2) echo -e "${RED}[✗] $message${NC}" ;;
        *) echo -e "$message" ;;
    esac
}

function main() {
    # Set up traps for proper cleanup
    setup_traps
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -a|--all)
                PERFORM_ALL=true
                ;;
            -m|--memory)
                PERFORM_MEMORY_ANALYSIS=true
                ;;
            -r|--rootkit)
                PERFORM_ROOTKIT_DETECTION=true
                ;;
            -n|--network)
                PERFORM_NETWORK_ANALYSIS=true
                ;;
            -c|--container)
                PERFORM_CONTAINER_ANALYSIS=true
                ;;
            -d|--malware)
                PERFORM_MALWARE_DETECTION=true
                ;;
            -t|--time)
                shift
                if [[ -n "$1" && "$1" =~ ^[0-9]+$ ]]; then
                    CAPTURE_DURATION="$1"
                else
                    echo -e "${RED}Error: --time requires a numeric value in seconds.${NC}"
                    display_help
                    exit 1
                fi
                ;;
            -o|--output)
                shift
                if [[ -n "$1" ]]; then
                    REPORT_FILE="$1"
                else
                    echo -e "${RED}Error: --output requires a filename.${NC}"
                    display_help
                    exit 1
                fi
                ;;
            -q|--quiet)
                QUIET_MODE=true
                ;;
            --debug)
                DEBUG_MODE=true
                ;;
            -h|--help)
                display_help
                exit 0
                ;;
            *)
                echo -e "${RED}Error: Unknown option: $1${NC}"
                display_help
                exit 1
                ;;
        esac
        shift
    done
    
    # If no specific analyses are selected, ask user or default to all
    if [[ $PERFORM_ALL == false && 
          $PERFORM_MEMORY_ANALYSIS == false && 
          $PERFORM_ROOTKIT_DETECTION == false && 
          $PERFORM_NETWORK_ANALYSIS == false && 
          $PERFORM_CONTAINER_ANALYSIS == false && 
          $PERFORM_MALWARE_DETECTION == false ]]; then
        
        echo -e "${YELLOW}No analysis modules selected. Run all modules? [Y/n] ${NC}"
        read -r response
        if [[ "$response" =~ ^([nN][oO]|[nN])$ ]]; then
            echo -e "${YELLOW}Exiting. Use --help to see available options.${NC}"
            exit 0
        else
            PERFORM_ALL=true
        fi
    fi
    
    # Set all flags if --all is selected
    if [[ $PERFORM_ALL == true ]]; then
        PERFORM_MEMORY_ANALYSIS=true
        PERFORM_ROOTKIT_DETECTION=true
        PERFORM_NETWORK_ANALYSIS=true
        PERFORM_CONTAINER_ANALYSIS=true
        PERFORM_MALWARE_DETECTION=true
    fi
    
    # Initialize the analysis environment
    initialize
    
    # Print analysis start information
    if [[ $QUIET_MODE == false ]]; then
        echo -e "${BOLD}${BLUE}Starting security analysis at $(date)${NC}"
        echo -e "${BLUE}===============================================${NC}"
        if [[ $PERFORM_MEMORY_ANALYSIS == true ]]; then
            echo -e "- Memory Forensics Analysis: ${GREEN}Enabled${NC}"
        else
            echo -e "- Memory Forensics Analysis: ${YELLOW}Disabled${NC}"
        fi
        if [[ $PERFORM_ROOTKIT_DETECTION == true ]]; then
            echo -e "- Rootkit Detection: ${GREEN}Enabled${NC}"
        else
            echo -e "- Rootkit Detection: ${YELLOW}Disabled${NC}"
        fi
        if [[ $PERFORM_NETWORK_ANALYSIS == true ]]; then
            echo -e "- Network Traffic Analysis: ${GREEN}Enabled${NC}"
        else
            echo -e "- Network Traffic Analysis: ${YELLOW}Disabled${NC}"
        fi
        if [[ $PERFORM_CONTAINER_ANALYSIS == true ]]; then
            echo -e "- Container Security Analysis: ${GREEN}Enabled${NC}"
        else
            echo -e "- Container Security Analysis: ${YELLOW}Disabled${NC}"
        fi
        if [[ $PERFORM_MALWARE_DETECTION == true ]]; then
            echo -e "- Custom Malware Detection: ${GREEN}Enabled${NC}"
        else
            echo -e "- Custom Malware Detection: ${YELLOW}Disabled${NC}"
        fi
        echo -e "${BLUE}===============================================${NC}\n"
    fi
    
    # Create header for report file
    echo -e "===============================================" > "$REPORT_FILE"
    echo -e "    ADVANCED SECURITY ANALYSIS REPORT     " >> "$REPORT_FILE"
    echo -e "===============================================" >> "$REPORT_FILE"
    echo -e "Date: $(date)" >> "$REPORT_FILE"
    echo -e "Host: $(hostname)" >> "$REPORT_FILE"
    echo -e "Kernel: $(uname -r)" >> "$REPORT_FILE"
    if [[ -f /etc/os-release ]]; then
        echo -e "OS: $(grep -E "^PRETTY_NAME=" /etc/os-release | cut -d= -f2 | tr -d '"')" >> "$REPORT_FILE"
    fi
    echo -e "===============================================\n" >> "$REPORT_FILE"
    
    # Keep track of overall execution status
    local overall_status=0
    
    # Execute selected analysis modules
    if [[ $PERFORM_MEMORY_ANALYSIS == true ]]; then
        echo -e "${BOLD}[1/5] Running memory forensics analysis...${NC}"
        perform_memory_analysis
        local status=$?
        overall_status=$((overall_status + status))
        
        if [[ $status -gt 0 ]]; then
            echo -e "${YELLOW}Memory analysis complete with ${BOLD}$status${NC}${YELLOW} suspicious findings.${NC}"
        else
            echo -e "${GREEN}Memory analysis complete with no suspicious findings.${NC}"
        fi
        echo -e ""
    fi
    
    if [[ $PERFORM_ROOTKIT_DETECTION == true ]]; then
        echo -e "${BOLD}[2/5] Running rootkit detection...${NC}"
        rootkit_detection
        local status=$?
        overall_status=$((overall_status + status))
        
        if [[ $status -gt 0 ]]; then
            echo -e "${YELLOW}Rootkit detection complete with ${BOLD}$status${NC}${YELLOW} suspicious findings.${NC}"
        else
            echo -e "${GREEN}Rootkit detection complete with no suspicious findings.${NC}"
        fi
        echo -e ""
    fi
    
    if [[ $PERFORM_NETWORK_ANALYSIS == true ]]; then
        echo -e "${BOLD}[3/5] Running network traffic analysis...${NC}"
        network_analysis
        local status=$?
        overall_status=$((overall_status + status))
        
        if [[ $status -gt 0 ]]; then
            echo -e "${YELLOW}Network analysis complete with ${BOLD}$status${NC}${YELLOW} suspicious findings.${NC}"
        else
            echo -e "${GREEN}Network analysis complete with no suspicious findings.${NC}"
        fi
        echo -e ""
    fi
    
    if [[ $PERFORM_CONTAINER_ANALYSIS == true ]]; then
        echo -e "${BOLD}[4/5] Running container security analysis...${NC}"
        container_security
        local status=$?
        overall_status=$((overall_status + status))
        
        if [[ $status -gt 0 ]]; then
            echo -e "${YELLOW}Container security analysis complete with ${BOLD}$status${NC}${YELLOW} issues found.${NC}"
        else
            echo -e "${GREEN}Container security analysis complete with no issues found.${NC}"
        fi
        echo -e ""
    fi
    
    if [[ $PERFORM_MALWARE_DETECTION == true && -f "$SIGNATURE_DIR/malware.yar" ]]; then
        echo -e "${BOLD}[5/5] Running custom malware detection...${NC}"
        log_info "Scanning system for malware signatures..."
        
        # Directories to scan for malware
        local scan_dirs=("/tmp" "/var/tmp" "/dev/shm" "/var/www" "/home" "/opt" "/usr/lib")
        local malware_found=0
        
        print_section_header "MALWARE DETECTION"
        echo -e "## Custom Malware Signature Analysis" >> "$REPORT_FILE"
        
        # Make sure YARA is available
        if command -v "$YARA_PATH" &>/dev/null; then
            for dir in "${scan_dirs[@]}"; do
                if [[ -d "$dir" ]]; then
                    echo -e "Scanning $dir for malware... "
                    "$YARA_PATH" -r "$SIGNATURE_DIR/malware.yar" "$dir" > "$TEMP_DIR/yara_scan_$(basename "$dir").txt" 2>/dev/null
                    
                    if [[ -s "$TEMP_DIR/yara_scan_$(basename "$dir").txt" ]]; then
                        local matches=$(wc -l < "$TEMP_DIR/yara_scan_$(basename "$dir").txt")
                        malware_found=$((malware_found + matches))
                        log_warning "Found $matches potential malware matches in $dir"
                        echo -e "\nPotential malware detected in $dir:" >> "$REPORT_FILE"
                        cat "$TEMP_DIR/yara_scan_$(basename "$dir").txt" >> "$REPORT_FILE"
                    else
                        log_success "No malware signatures found in $dir"
                    fi
                fi
            done
            
            # Additional specific file scans
            log_info "Scanning suspicious file types across the system..."
            find / -type f -name "*.sh" -o -name "*.php" -o -name "*.cgi" -path "*/tmp/*" -o -path "*/dev/shm/*" 2>/dev/null | \
            while read -r file; do
                "$YARA_PATH" "$SIGNATURE_DIR/malware.yar" "$file" >> "$TEMP_DIR/yara_scan_suspicious_files.txt" 2>/dev/null
            done
            
            if [[ -s "$TEMP_DIR/yara_scan_suspicious_files.txt" ]]; then
                local matches=$(wc -l < "$TEMP_DIR/yara_scan_suspicious_files.txt")
                malware_found=$((malware_found + matches))
                log_warning "Found $matches potential malware matches in suspicious files"
                echo -e "\nPotential malware detected in suspicious files:" >> "$REPORT_FILE"
                cat "$TEMP_DIR/yara_scan_suspicious_files.txt" >> "$REPORT_FILE"
            fi
            
            # Scan cron jobs
            find /etc/cron* /var/spool/cron -type f 2>/dev/null | \
            while read -r file; do
                "$YARA_PATH" "$SIGNATURE_DIR/malware.yar" "$file" >> "$TEMP_DIR/yara_scan_cron.txt" 2>/dev/null
            done
            
            if [[ -s "$TEMP_DIR/yara_scan_cron.txt" ]]; then
                local matches=$(wc -l < "$TEMP_DIR/yara_scan_cron.txt")
                malware_found=$((malware_found + matches))
                log_warning "Found $matches potential malware matches in cron jobs"
                echo -e "\nPotential malware detected in cron jobs:" >> "$REPORT_FILE"
                cat "$TEMP_DIR/yara_scan_cron.txt" >> "$REPORT_FILE"
            fi
            
            # Report summary
            echo -e "\n## Malware Detection Summary" >> "$REPORT_FILE"
            if [[ $malware_found -gt 0 ]]; then
                log_warning "Malware detection complete. Found $malware_found potential malware matches."
                echo -e "Total potential malware matches found: $malware_found\nRecommendation: Review the detailed findings and investigate detected files further." >> "$REPORT_FILE"
                overall_status=$((overall_status + malware_found))
            else
                log_success "Malware detection complete. No malware signatures found."
                echo -e "No malware signatures found.\nRecommendation: Continue with regular security monitoring." >> "$REPORT_FILE"
            fi
        else
            log_warning "YARA not found. Malware detection skipped."
            echo -e "YARA not found. Malware detection skipped." >> "$REPORT_FILE"
        fi
    fi
    
    # Generate the final security report with risk assessment
    echo -e "${BOLD}Generating comprehensive security report...${NC}"
    generate_final_report
    local risk_level=$?
    
    # Display analysis completion message
    echo -e "\n${BOLD}${GREEN}Security analysis complete!${NC}"
    echo -e "${BOLD}Summary:${NC}"
    echo -e "- Issues found: ${BOLD}$overall_status${NC}"
    echo -e "- Risk level: ${BOLD}$(
        if [[ $risk_level -eq 0 ]]; then echo -e "${GREEN}Low${NC}"; 
        elif [[ $risk_level -eq 1 ]]; then echo -e "${YELLOW}Medium${NC}"; 
        elif [[ $risk_level -eq 2 ]]; then echo -e "${RED}High${NC}"; 
        else echo -e "${RED}Critical${NC}"; fi
    )${NC}"
    echo -e "- Detailed report: ${BOLD}$REPORT_FILE${NC}"
    
    # Return overall risk level as exit code
    return $risk_level
}

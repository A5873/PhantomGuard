#!/bin/bash

#############################################################
# System Security Checker
# 
# Purpose: This script performs security checks on a Linux
# system to identify potential security issues, suspicious
# activities, and signs of compromise.
#
# Features:
# - System file integrity checking
# - Detection of suspicious processes and services
# - Identification of potential rootkits
# - Network connection analysis
# - Permission and configuration auditing
# - Log analysis for security events
#
# Usage: ./system_security_checker.sh
#
# Note: This script must be run as root to access all
# system information required for thorough checking.
#############################################################

# Color definitions for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}${BOLD}Error:${NC} This script must be run as root" 
   echo "Please run with sudo or as root user"
   exit 1
fi

# Display banner
display_banner() {
    echo -e "${BLUE}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║                                                       ║"
    echo "║             SYSTEM SECURITY CHECKER                   ║"
    echo "║                                                       ║"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}Performing security assessment of the system...${NC}\n"
}

# Function to check for suspicious processes
check_processes() {
    echo -e "\n${CYAN}${BOLD}[+] Checking for suspicious processes...${NC}"
    
    # Helper function to convert process ID to process name
    pid_to_name() {
        local pid=$1
        if [ -f "/proc/$pid/comm" ]; then
            cat "/proc/$pid/comm" 2>/dev/null
        else
            echo "unknown"
        fi
    }
    
    # 1. Check for processes with no associated binary
    echo -e "\n${YELLOW}[*] Checking for processes with no associated binary:${NC}"
    ps aux | awk 'NR > 1 {print $2}' | while read pid; do
        if [ -d "/proc/$pid" ]; then
            if [ ! -e "/proc/$pid/exe" ] || [ ! -r "/proc/$pid/exe" ] || [ -z "$(readlink /proc/$pid/exe 2>/dev/null)" ]; then
                process_name=$(pid_to_name "$pid")
                echo -e "${RED}Process $pid ($process_name) has no associated binary or unreadable exe link${NC}"
                echo -e "Command: $(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')"
                echo -e "Status: $(grep State /proc/$pid/status 2>/dev/null)"
            fi
        fi
    done
    
    # 2. Check for processes running from temporary directories or unusual locations
    echo -e "\n${YELLOW}[*] Checking for processes running from suspicious locations:${NC}"
    ps aux | grep -v "^USER" | while read line; do
        pid=$(echo "$line" | awk '{print $2}')
        if [ -e "/proc/$pid/exe" ]; then
            exe_path=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
            if [[ "$exe_path" == *"/tmp/"* || 
                  "$exe_path" == *"/dev/shm/"* || 
                  "$exe_path" == *"/var/tmp/"* || 
                  "$exe_path" == *"/run/user/"* || 
                  "$exe_path" == "/tmp" || 
                  "$exe_path" == "/dev/shm" || 
                  "$exe_path" == "/var/tmp" ]]; then
                echo -e "${RED}Suspicious process location:${NC} PID: $pid, Path: $exe_path"
                echo -e "Command: $(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')"
                echo -e "Owner: $(ls -l /proc/$pid 2>/dev/null | grep exe | awk '{print $3}')"
            fi
        fi
    done
    
    # 3. Compare process list between ps and /proc to find hidden processes
    echo -e "\n${YELLOW}[*] Checking for hidden processes (comparing ps output with /proc):${NC}"
    ps_pids=$(ps -e -o pid h | sort -n)
    proc_pids=$(find /proc -maxdepth 1 -regex '/proc/[0-9]+' | sed 's/\/proc\///' | sort -n)
    
    # Find PIDs in /proc but not in ps output (potentially hidden)
    for pid in $proc_pids; do
        if [[ ! $ps_pids =~ (^|[[:space:]])$pid($|[[:space:]]) ]]; then
            # Verify it's a real process and not just a transient process
            if [ -e "/proc/$pid/status" ]; then
                process_name=$(pid_to_name "$pid")
                echo -e "${RED}Hidden process detected:${NC} PID: $pid, Name: $process_name"
                echo -e "Command: $(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')"
                echo -e "Status: $(grep State /proc/$pid/status 2>/dev/null)"
                echo -e "Owner: $(ls -ld /proc/$pid 2>/dev/null | awk '{print $3}')"
            fi
        fi
    done
    
    # 4. Check for processes with high CPU usage
    echo -e "\n${YELLOW}[*] Checking for processes with high CPU usage:${NC}"
    high_cpu_procs=$(ps aux | awk '$3 > 50.0 {print $2 " " $3 " " $11}')
    if [ -n "$high_cpu_procs" ]; then
        echo -e "${RED}Processes with high CPU usage:${NC}"
        echo "PID    CPU%   COMMAND"
        echo "$high_cpu_procs"
        
        # Get more details about these processes
        echo -e "${YELLOW}Details of high CPU processes:${NC}"
        echo "$high_cpu_procs" | awk '{print $1}' | while read pid; do
            if [ -d "/proc/$pid" ]; then
                echo -e "PID: $pid"
                echo -e "Exe: $(readlink -f /proc/$pid/exe 2>/dev/null)"
                echo -e "Command: $(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')"
                echo -e "Owner: $(ls -ld /proc/$pid 2>/dev/null | awk '{print $3}')"
                echo -e "Started: $(ps -p $pid -o lstart=)"
                echo "----------------------------------------"
            fi
        done
    else
        echo -e "${GREEN}No processes with high CPU usage detected.${NC}"
    fi
    
    # Additional check: Look for processes with suspicious names (common malware patterns)
    echo -e "\n${YELLOW}[*] Checking for processes with suspicious names:${NC}"
    ps aux | grep -v grep | grep -iE '\b(xmr|miner|coin|monero|crypto|kworker[^s]|kdevtmpfsi|ksoftirq|kworkerds|kthreaded|kswapd0|gifsk|crypto|zzh|kwoker|minerd)\b' | grep -v "check_processes"
    if [ $? -eq 0 ]; then
        echo -e "${RED}Found processes with potentially suspicious names!${NC}"
    else
        echo -e "${GREEN}No processes with suspicious names detected.${NC}"
    fi
}

# Function to check for suspicious network connections
check_network() {
    echo -e "\n${CYAN}${BOLD}[+] Checking network connections...${NC}"
    
    # Check if required tools are available
    if ! command -v ss &> /dev/null; then
        echo -e "${YELLOW}Warning: 'ss' command not found. Some network checks may be limited.${NC}"
    fi
    
    # 1. List all listening ports and associated processes
    echo -e "\n${YELLOW}[*] Checking for listening ports and their associated processes:${NC}"
    if command -v ss &> /dev/null; then
        listening_ports=$(ss -tuln)
        listening_procs=$(ss -tulnp)
        echo -e "${WHITE}Listening ports:${NC}"
        echo "$listening_ports" | grep -E 'LISTEN'
        echo -e "\n${WHITE}Processes associated with listening ports:${NC}"
        echo "$listening_procs" | grep -E 'LISTEN'
        
        # Identify unusual ports
        echo -e "\n${YELLOW}[*] Checking for uncommon listening ports:${NC}"
        unusual_ports=$(ss -tuln | grep -E 'LISTEN' | grep -vE ':((22|53|80|443|3306|5432|27017|8080|8443|25|587|993|995|143|110|21|20|989|990|636|389|137|138|139|445|3389|1433|3307|5672|6379|11211|9200|9300|7001|7002|161|123|88)([:[:space:]])|\[::1\])')
        if [ -n "$unusual_ports" ]; then
            echo -e "${RED}Unusual listening ports detected:${NC}"
            echo "$unusual_ports"
        else
            echo -e "${GREEN}No unusual listening ports detected.${NC}"
        fi
    else
        # Fallback to netstat if ss is not available
        echo -e "${YELLOW}Using netstat as fallback${NC}"
        netstat -tuln | grep LISTEN
        netstat -tulnp | grep LISTEN
    fi
    
    # 2. Check for connections to known malicious ports
    echo -e "\n${YELLOW}[*] Checking for connections to known malicious ports:${NC}"
    # Define list of commonly used malicious ports
    malicious_ports=(
        "1080"  # SOCKS proxy commonly used by malware
        "1337"  # Common backdoor port
        "4444"  # Metasploit default listener
        "5555"  # Common Android Debug Bridge exploit port
        "6666"  # Common IRC bot port
        "6667"  # Common IRC bot port
        "6668"  # Common IRC bot port
        "6669"  # Common IRC bot port
        "8087"  # Common botnet C&C port
        "9001"  # Common Tor port
        "9050"  # Common Tor port
        "9051"  # Common Tor port
        "31337" # Elite backdoor port
    )
    
    malicious_port_pattern=$(IFS="|"; echo "${malicious_ports[*]}")
    suspicious_conns=$(ss -tupn | grep -E ":(${malicious_port_pattern})[[:space:]]" || true)
    
    if [ -n "$suspicious_conns" ]; then
        echo -e "${RED}Suspicious connections to potentially malicious ports:${NC}"
        echo "$suspicious_conns"
    else
        echo -e "${GREEN}No connections to known malicious ports detected.${NC}"
    fi
    
    # 3. Identify processes with unexpected network activity
    echo -e "\n${YELLOW}[*] Checking for processes with unexpected network activity:${NC}"
    # Common system processes that should have network connections
    system_net_procs=("sshd" "apache2" "nginx" "httpd" "mysqld" "named" "ntpd" "chronyd" "postfix" "dovecot" "smbd" "nmbd" "cupsd" "dhclient" "NetworkManager" "dockerd" "containerd" "syslogd" "rsyslogd" "systemd-resolved")
    
    # Get all processes with network connections
    net_processes=$(ss -tupn | grep -v "LISTEN" | awk '{print $6}' | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u)
    
    for pid in $net_processes; do
        if [ -e "/proc/$pid/comm" ]; then
            proc_name=$(cat "/proc/$pid/comm" 2>/dev/null)
            proc_exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null)
            proc_cmdline=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ')
            
            # Check if this is not a common network process
            is_expected=0
            for sys_proc in "${system_net_procs[@]}"; do
                if [[ "$proc_name" == "$sys_proc" || "$proc_cmdline" == *"$sys_proc"* ]]; then
                    is_expected=1
                    break
                fi
            done
            
            # If not a common network process, report it
            if [ $is_expected -eq 0 ]; then
                echo -e "${YELLOW}Process with unexpected network activity:${NC}"
                echo -e "PID: $pid"
                echo -e "Name: $proc_name"
                echo -e "Executable: $proc_exe"
                echo -e "Command: $proc_cmdline"
                echo -e "Network connections:"
                ss -tupn | grep "pid=$pid" | sed 's/^/  /'
                echo "-----------------------------------"
            fi
        fi
    done
    
    # 4. Check for suspicious DNS queries
    echo -e "\n${YELLOW}[*] Checking for suspicious DNS queries:${NC}"
    
    # First check if we can access DNS query history
    if [ -d "/var/log/syslog" ] || [ -f "/var/log/syslog" ]; then
        echo -e "${WHITE}Checking system logs for DNS queries...${NC}"
        suspicious_dns=$(grep -i "query" /var/log/syslog* 2>/dev/null | grep -iE '\.(xyz|tk|ml|ga|cf|gq|top|ru|cn|su|ws|biz|info|online|site|club|stream|pw|cc|racing|party|review|trade|date|faith|win|science|work|men|loan|gdn|bid|black|stream|cricket|space|rest|trade|kim|accountant|country|rest|mom)' || true)
        
        if [ -n "$suspicious_dns" ]; then
            echo -e "${RED}Suspicious DNS queries detected:${NC}"
            echo "$suspicious_dns" | tail -n 20
        else
            echo -e "${GREEN}No suspicious DNS queries found in logs.${NC}"
        fi
    elif command -v tcpdump &> /dev/null; then
        echo -e "${YELLOW}Performing brief DNS traffic analysis (5 seconds)...${NC}"
        echo -e "${WHITE}Press Ctrl+C if this takes too long...${NC}"
        timeout 5 tcpdump -nn -i any port 53 2>/dev/null | grep -i "A?" || true
    else
        echo -e "${YELLOW}Cannot check DNS queries - no sufficient logs or tools found.${NC}"
    fi
    
    # Check /etc/resolv.conf for unusual DNS servers
    echo -e "\n${YELLOW}[*] Checking for unusual DNS servers:${NC}"
    grep "nameserver" /etc/resolv.conf | grep -v "127.0.0.1" | grep -v "1.1.1.1" | grep -v "8.8.8.8" | grep -v "8.8.4.4" | grep -v "9.9.9.9" || true
    
    # 5. Look for unusual outbound connections
    echo -e "\n${YELLOW}[*] Checking for unusual outbound connections:${NC}"
    
    # Get established outbound connections
    outbound=$(ss -tupn | grep ESTAB | grep -v "127.0.0.1" | grep -v "::1" || true)
    
    if [ -n "$outbound" ]; then
        echo -e "${WHITE}Current outbound connections:${NC}"
        echo "$outbound"
        
        # Check for connections to non-standard ports
        echo -e "\n${YELLOW}Connections to non-standard ports:${NC}"
        echo "$outbound" | grep -vE ":(22|53|80|443|3306|5432|27017|8080|8443|25|587|993|995|143|110|21|20|989|990|636|389)[[:space:]]" || echo -e "${GREEN}None found.${NC}"
        
        # Check for high number of outbound connections from single process
        echo -e "\n${YELLOW}Processes with high number of outbound connections:${NC}"
        conn_count=$(echo "$outbound" | awk '{print $6}' | grep -oE 'pid=[0-9]+' | sort | uniq -c | sort -nr)
        echo "$conn_count" | while read count pid; do
            if [ "$count" -gt 10 ]; then
                pid_num=$(echo "$pid" | grep -oE '[0-9]+')
                proc_name=$(cat "/proc/$pid_num/comm" 2>/dev/null || echo "unknown")
                echo -e "${RED}Process $proc_name ($pid_num) has $count outbound connections${NC}"
            fi
        done
    else
        echo -e "${GREEN}No unusual outbound connections detected.${NC}"
    fi
    
    # Check if IPv6 connections could be used to bypass firewall rules
    echo -e "\n${YELLOW}[*] Checking for IPv6 connections that might bypass IPv4 firewall rules:${NC}"
    ipv6_conns=$(ss -6tupn | grep -v "::1" || true)
    if [ -n "$ipv6_conns" ]; then
        echo -e "${YELLOW}IPv6 connections detected - verify these are expected:${NC}"
        echo "$ipv6_conns"
    else
        echo -e "${GREEN}No IPv6 connections detected.${NC}"
    fi
}

# Function to check for modified system files
check_system_files() {
    echo -e "\n${CYAN}${BOLD}[+] Checking system file integrity...${NC}"
    
    # Define critical system directories and binaries to check
    critical_dirs=(
        "/bin"
        "/sbin"
        "/usr/bin"
        "/usr/sbin"
        "/usr/local/bin"
        "/usr/local/sbin"
        "/etc"
        "/lib"
        "/lib64"
        "/usr/lib"
        "/usr/lib64"
    )
    
    critical_binaries=(
        "/bin/ls"
        "/bin/ps"
        "/bin/netstat"
        "/bin/ss"
        "/bin/ip"
        "/bin/bash"
        "/bin/dash"
        "/bin/sh"
        "/usr/bin/sudo"
        "/usr/bin/find"
        "/usr/bin/grep"
        "/usr/bin/top"
        "/sbin/ifconfig"
        "/sbin/route"
        "/usr/bin/passwd"
        "/usr/bin/ssh"
        "/usr/bin/curl"
        "/usr/bin/wget"
        "/usr/bin/who"
        "/usr/bin/whoami"
    )
    
    # Helper function to determine if a file was modified recently
    file_modified_recently() {
        local file=$1
        local threshold_days=${2:-30}  # Default to 30 days
        
        if [ ! -f "$file" ]; then
            return 1
        fi
        
        local mtime=$(stat -c %Y "$file" 2>/dev/null)
        local current_time=$(date +%s)
        local threshold_seconds=$((threshold_days * 86400))
        
        if (( current_time - mtime < threshold_seconds )); then
            return 0  # True - modified recently
        else
            return 1  # False - not modified recently
        fi
    }
    
    # Helper function to check file hash
    verify_file_integrity() {
        local file=$1
        
        # Skip if file doesn't exist
        if [ ! -f "$file" ]; then
            return 1
        fi
        
        # Create a simple hash of the file
        local file_hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
        
        # Check against known good hashes if available (in a real system, you'd have a database of known good hashes)
        # For now, just report the hash for manual verification
        echo "$file: $file_hash"
    }
    
    # 1. Check for modified timestamps on critical system binaries
    echo -e "\n${YELLOW}[*] Checking for recently modified system binaries:${NC}"
    
    for binary in "${critical_binaries[@]}"; do
        if [ -f "$binary" ]; then
            if file_modified_recently "$binary" 30; then
                echo -e "${RED}Warning: System binary recently modified:${NC} $binary"
                echo -e "  Last modified: $(stat -c '%y' "$binary")"
                echo -e "  Owner: $(stat -c '%U:%G' "$binary")"
                echo -e "  Permissions: $(stat -c '%A' "$binary")"
            fi
        fi
    done
    
    # 2. Look for hidden files in system directories
    echo -e "\n${YELLOW}[*] Checking for hidden files in system directories:${NC}"
    
    for dir in "${critical_dirs[@]}"; do
        if [ -d "$dir" ]; then
            hidden_files=$(find "$dir" -name ".*" -type f -not -path "*/\.*" 2>/dev/null)
            
            if [ -n "$hidden_files" ]; then
                echo -e "${RED}Found hidden files in $dir:${NC}"
                echo "$hidden_files" | while read hidden_file; do
                    echo -e "  $hidden_file ($(stat -c '%U:%G %A' "$hidden_file"))"
                done
            fi
        fi
    done
    
    # 3. Check for files with unusual permissions
    echo -e "\n${YELLOW}[*] Checking for files with unusual permissions:${NC}"
    
    # Look for world-writable files in system directories
    for dir in "${critical_dirs[@]}"; do
        if [ -d "$dir" ]; then
            world_writable=$(find "$dir" -type f -perm -o+w -not -path "*/proc/*" 2>/dev/null)
            
            if [ -n "$world_writable" ]; then
                echo -e "${RED}Found world-writable files in $dir:${NC}"
                echo "$world_writable" | while read file; do
                    echo -e "  $file ($(stat -c '%U:%G %A' "$file"))"
                done
            fi
        fi
    done
    
    # Look for SUID/SGID files not typically set that way
    echo -e "\n${YELLOW}[*] Checking for unusual SUID/SGID files:${NC}"
    unusual_suid=$(find / -type f \( -perm -4000 -o -perm -2000 \) -not -path "*/proc/*" -not -path "*/dev/*" 2>/dev/null)
    
    # Common legitimate SUID/SGID binaries
    common_suid=(
        "/bin/su"
        "/bin/mount"
        "/bin/umount"
        "/usr/bin/sudo"
        "/usr/bin/passwd"
        "/usr/bin/gpasswd"
        "/usr/bin/chfn"
        "/usr/bin/chsh"
        "/usr/bin/newgrp"
        "/usr/bin/pkexec"
    )
    
    echo "$unusual_suid" | while read file; do
        is_common=0
        for common in "${common_suid[@]}"; do
            if [ "$file" = "$common" ]; then
                is_common=1
                break
            fi
        done
        
        if [ $is_common -eq 0 ]; then
            echo -e "${RED}Unusual SUID/SGID file:${NC} $file ($(stat -c '%U:%G %A' "$file"))"
        fi
    done
    
    # 4. Monitor recent file modifications
    echo -e "\n${YELLOW}[*] Checking for recent file modifications in critical directories:${NC}"
    
    for dir in "${critical_dirs[@]}"; do
        if [ -d "$dir" ]; then
            # Find files modified in the last 7 days
            recent_files=$(find "$dir" -type f -mtime -7 -not -path "*/\.*" 2>/dev/null)
            
            if [ -n "$recent_files" ]; then
                echo -e "${YELLOW}Recently modified files in $dir:${NC}"
                echo "$recent_files" | head -n 10 | while read file; do
                    echo -e "  $file (modified: $(stat -c '%y' "$file"))"
                done
                
                # If there are many files, just show count
                count=$(echo "$recent_files" | wc -l)
                if [ $count -gt 10 ]; then
                    echo -e "  ... and $((count - 10)) more files"
                fi
            fi
        fi
    done
    
    # 5. Verify integrity of important system files
    echo -e "\n${YELLOW}[*] Verifying integrity of important system files:${NC}"
    
    # If the system has debsums, use it (for Debian-based systems)
    if command -v debsums &> /dev/null; then
        echo -e "${WHITE}Running debsums to verify installed packages...${NC}"
        debsums_output=$(debsums -c 2>/dev/null)
        if [ -n "$debsums_output" ]; then
            echo -e "${RED}Debsums found modified files:${NC}"
            echo "$debsums_output"
        else
            echo -e "${GREEN}Debsums verification passed.${NC}"
        fi
    # If the system has rpm, use it (for RPM-based systems)
    elif command -v rpm &> /dev/null; then
        echo -e "${WHITE}Running rpm verification...${NC}"
        rpm_output=$(rpm -Va --nomtime --nomode --nomd5 2>/dev/null | grep -v '\.conf')
        if [ -n "$rpm_output" ]; then
            echo -e "${RED}RPM verification found modified files:${NC}"
            echo "$rpm_output" | head -n 20
            count=$(echo "$rpm_output" | wc -l)
            if [ $count -gt 20 ]; then
                echo -e "  ... and $((count - 20)) more files with verification issues"
            fi
        else
            echo -e "${GREEN}RPM verification passed.${NC}"
        fi
    # If neither is available, check critical files manually
    else
        echo -e "${WHITE}Computing hashes of critical system files for manual verification:${NC}"
        for binary in "${critical_binaries[@]}"; do
            if [ -f "$binary" ]; then
                verify_file_integrity "$binary"
            fi
        done
    fi
    
    # Check for core file tampering
    echo -e "\n${YELLOW}[*] Checking for signs of kernel module/rootkit injection:${NC}"
    
    # Check if the system has unusual kernel modules loaded
    unusual_modules=$(lsmod | grep -v -E '(snd|video|crypto|net|scsi|usb|serial|bluetooth|thermal|button|acpi|power|media|i2c|input|mac|sg|asoc|mmc)' || true)
    if [ -n "$unusual_modules" ]; then
        echo -e "${RED}Unusual kernel modules detected:${NC}"
        echo "$unusual_modules" | head -n 10
    else
        echo -e "${GREEN}No unusual kernel modules detected.${NC}"
    fi
    
    # Check for signs of /dev tampering
    echo -e "\n${YELLOW}[*] Checking for suspicious devices in /dev:${NC}"
    suspicious_devs=$(find /dev -type c -not -path "*/shm/*" -not -path "*/pts/*" -name "*.?" 2>/dev/null)
    if [ -n "$suspicious_devs" ]; then
        echo -e "${RED}Suspicious device files detected:${NC}"
        echo "$suspicious_devs"
    else
        echo -e "${GREEN}No suspicious device files detected.${NC}"
    fi
}

# Function to check common rootkit indicators
check_rootkits() {
    echo -e "\n${CYAN}${BOLD}[+] Checking for rootkit indicators...${NC}"
    
    # Helper function to check if a path exists (file or directory)
    path_exists() {
        [ -e "$1" ]
    }

    # 1. Check for known rootkit files and directories
    echo -e "\n${YELLOW}[*] Checking for known rootkit files and directories:${NC}"
    
    # List of known rootkit files and directories
    known_rootkit_paths=(
        # Common rootkit files
        "/dev/.hdlc"               # Suckit rootkit
        "/dev/.udev"               # Pidruid rootkit
        "/dev/.indtmp"             # Romanian rootkit
        "/dev/.rdisk0"             # Knark rootkit
        "/dev/.shit"               # Omega rootkit
        "/dev/.secret"             # Various rootkits
        "/dev/ttyop"               # Mithril rootkit
        "/dev/ttyoa"               # Mithril rootkit
        "/dev/hda06"               # Various rootkits
        "/dev/hda07"               # Various rootkits
        "/dev/ttyof"               # Mithril rootkit
        "/dev/ttyos"               # Mithril rootkit
        "/dev/ptmx"                # Various rootkits (check for ownership)
        "/etc/.pwd.lock"           # Various rootkits
        "/lib/modules/`uname -r`/kernel/drivers/net/soundx" # Enye LKM
        "/lib/.libpty.so"          # Various rootkits
        "/lib/.libsound.so"        # Various rootkits
        "/usr/lib/.libsound.so"    # Various rootkits
        "/usr/lib/.libproc.so"     # Various rootkits
        "/usr/lib/.libnetsound.so" # Various rootkits
        "/usr/bin/soundxfer"       # Enye LKM
        "/usr/bin/xsf"             # Flea Linux LKM
        "/usr/bin/adore"           # Adore rootkit
        "/sbin/xlogin"             # Rootkits
        "/sbin/.login"             # Rootkits
        "/sbin/initsx"             # Rootkits
        "/sbin/init.old"           # Rootkits
        "/usr/include/.sith"       # Rootkits
        "/etc/rc.d/rc0.d/x"        # Rootkits
        "/usr/man/man1/lib/.lib"   # Rootkits
        "/usr/man/man1/lib/.lib/.backup/.x" # Rootkits
        "/tmp/.cheese"             # Rootkits
        "/tmp/.dump"               # Rootkits
        "/var/lock/.ghost"         # Rootkits
        "/var/lock/.kpid"          # Rootkits
        "/tmp/.fixrtc"             # Suckit rootkit
        "/tmp/.font-unix"          # Rootkits
        "/tmp/.ICE-unix/.tmp-unix" # Rootkits
        "/tmp/.X11-unix/.tmp-unix" # Rootkits
        "/proc/.kmem"              # Rootkits
        "/proc/.modules"           # Rootkits
        "/etc/X11/.X11R6"          # Rootkits
        "/usr/include/.wormie"     # Rootkits
        "/usr/lib/.kinetic"        # Rootkits
        "/usr/share/.make"         # Rootkits
        "/var/run/.pid"            # Rootkits
    )
    
    found_suspicious_files=0
    
    for path in "${known_rootkit_paths[@]}"; do
        if path_exists "$path"; then
            echo -e "${RED}Potential rootkit found: ${path}${NC}"
            ls -la "$path" 2>/dev/null
            file "$path" 2>/dev/null
            found_suspicious_files=1
        fi
    done
    
    # Check for hidden directories in unusual places
    for dir in /dev /etc /lib /usr/lib /bin /sbin /usr/bin /usr/sbin /var/run /tmp; do
        hidden_dirs=$(find "$dir" -maxdepth 1 -type d -name ".*" 2>/dev/null | grep -v '\.\./$' | grep -v '\.\/$')
        if [ -n "$hidden_dirs" ]; then
            echo -e "${RED}Suspicious hidden directories found:${NC}"
            echo "$hidden_dirs" | while read -r hdir; do
                echo -e "${RED}$hdir${NC} ($(ls -ld "$hdir" 2>/dev/null))"
                found_suspicious_files=1
            done
        fi
    done
    
    if [ $found_suspicious_files -eq 0 ]; then
        echo -e "${GREEN}No known rootkit files or directories found.${NC}"
    fi
    
    # 2. Detect process hiding techniques
    echo -e "\n${YELLOW}[*] Checking for process hiding techniques:${NC}"
    
    # Compare different process listing methods
    echo -e "${WHITE}Comparing different process listing methods to find hidden processes...${NC}"
    
    # Get processes from ps command
    ps_processes=$(ps -ef | awk '{print $2}' | sort -n)
    
    # Get processes from /proc
    proc_processes=$(find /proc -maxdepth 1 -regex '/proc/[0-9]+' 2>/dev/null | cut -d/ -f3 | sort -n)
    
    # Get processes from sysfs (if available)
    if [ -d "/sys/fs/cgroup/pids" ]; then
        cgroup_processes=$(find /sys/fs/cgroup/pids -name tasks -exec cat {} \; 2>/dev/null | sort -n | uniq)
    else
        cgroup_processes=""
    fi
    
    # Compare ps with /proc
    echo -e "${WHITE}Checking for processes visible in /proc but not in 'ps' output (possible LKM rootkit):${NC}"
    hidden_from_ps=0
    for pid in $proc_processes; do
        if ! echo "$ps_processes" | grep -q "^$pid$"; then
            # Verify it's a real process and not just a transient process
            if [ -e "/proc/$pid/status" ]; then
                proc_name=$(cat "/proc/$pid/comm" 2>/dev/null || echo "unknown")
                echo -e "${RED}Process hiding detected: PID $pid ($proc_name) visible in /proc but hidden from ps${NC}"
                echo -e "Command: $(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')"
                echo -e "Status: $(grep State /proc/$pid/status 2>/dev/null)"
                echo -e "Owner: $(ls -ld /proc/$pid 2>/dev/null | awk '{print $3}')"
                hidden_from_ps=1
            fi
        fi
    done
    
    if [ $hidden_from_ps -eq 0 ]; then
        echo -e "${GREEN}No processes hidden from ps command detected.${NC}"
    fi
    
    # Check /proc/<pid>/maps for suspicious libraries
    echo -e "\n${WHITE}Checking for suspicious libraries loaded in processes:${NC}"
    
    suspicious_libs=0
    for pid in $(ps -ef | awk '{print $2}'); do
        if [ -r "/proc/$pid/maps" ]; then
            suspicious=$(grep -i "dev/shm\|\.so\.$\|/tmp/" /proc/$pid/maps 2>/dev/null)
            if [ -n "$suspicious" ]; then
                echo -e "${RED}Process $pid has suspicious libraries:${NC}"
                ps -p $pid -o user,pid,cmd
                echo "$suspicious"
                suspicious_libs=1
            fi
        fi
    done
    
    if [ $suspicious_libs -eq 0 ]; then
        echo -e "${GREEN}No suspicious libraries found in process memory.${NC}"
    fi
    
    # 3. Identify suspicious kernel modules
    echo -e "\n${YELLOW}[*] Checking for suspicious kernel modules:${NC}"
    
    # Known malicious module names or patterns
    suspicious_module_patterns=(
        "adore"
        "ipsuk"
        "knark"
        "redir"
        "suckit"
        "invisible"
        "modhide"
        "cleaner"
        "heroin"
        "nethide"
        "portknock"
        "phide"
        "override"
        "placebo"
        "shv"
        "amark"
        "hide"
        "ssniffer"
        "ork"
        "kinsmod"
        "wkmr"
        "kbeast"
        "diamorphine"
    )
    
    # Get loaded kernel modules
    loaded_modules=$(lsmod | tail -n +2 | awk '{print $1}')
    
    # Check for suspicious module names
    found_suspicious_modules=0
    for module in $loaded_modules; do
        for pattern in "${suspicious_module_patterns[@]}"; do
            if echo "$module" | grep -qi "$pattern"; then
                echo -e "${RED}Potentially malicious kernel module: $module${NC}"
                modinfo "$module" 2>/dev/null || echo "No module info available"
                found_suspicious_modules=1
            fi
        done
    done
    
    # Check if modules are loaded but not shown in lsmod
    if [ -d "/sys/module" ]; then
        sys_modules=$(ls -1 /sys/module 2>/dev/null)
        for module in $sys_modules; do
            if ! echo "$loaded_modules" | grep -q "$module"; then
                echo -e "${RED}Hidden kernel module detected: $module exists in /sys/module but not shown by lsmod${NC}"
                found_suspicious_modules=1
            fi
        done
    fi
    
    # Check for abnormally small modules (typically hidden functionality)
    for module in $loaded_modules; do
        module_size=$(lsmod | grep "^$module" | awk '{print $2}')
        if [ "$module_size" -lt 5 ] 2>/dev/null; then
            echo -e "${RED}Suspiciously small kernel module: $module (size: $module_size)${NC}"
            found_suspicious_modules=1
        fi
    done
    
    if [ $found_suspicious_modules -eq 0 ]; then
        echo -e "${GREEN}No suspicious kernel modules detected.${NC}"
    fi
    
    # Check module directory for suspicious files
    module_dir="/lib/modules/$(uname -r)"
    if [ -d "$module_dir" ]; then
        echo -e "\n${WHITE}Checking module directory for suspicious files:${NC}"
        suspicious_files=$(find "$module_dir" -name "*.ko" -exec file {} \; | grep -v "kernel module")
        
        if [ -n "$suspicious_files" ]; then
            echo -e "${RED}Found suspicious files in kernel module directory:${NC}"
            echo "$suspicious_files"
        else
            echo -e "${GREEN}No suspicious files found in kernel module directory.${NC}"
        fi
    fi
    
    # 4. Check for system call table modifications
    echo -e "\n${YELLOW}[*] Checking for system call table modifications:${NC}"
    
    # This check requires access to /dev/kmem or a kernel with kallsyms support
    if [ -f "/proc/kallsyms" ]; then
        echo -e "${WHITE}Checking system call table addresses from /proc/kallsyms...${NC}"
        
        # Get the base address of the system call table
        sys_call_table=$(grep -E "sys_call_table|sct" /proc/kallsyms 2>/dev/null | head -n1)
        
        if [ -n "$sys_call_table" ]; then
            base_addr=$(echo "$sys_call_table" | awk '{print $1}')
            echo -e "System call table base address: $base_addr"
            
            # Check for hooks in common system calls
            popular_syscalls=("sys_read" "sys_write" "sys_open" "sys_close" "sys_execve" "sys_access" "sys_mkdir" "sys_unlink")
            
            for syscall in "${popular_syscalls[@]}"; do
                sym_addr=$(grep " $syscall$" /proc/kallsyms 2>/dev/null | awk '{print $1}')
                if [ -n "$sym_addr" ]; then
                    # Check if the address is outside the kernel text segment
                    # This is a very simplified check and not completely reliable
                    if [[ "$sym_addr" < "0xffffffff80000000" || "$sym_addr" > "0xffffffffa0000000" ]]; then
                        echo -e "${RED}Suspicious system call address for $syscall: $sym_addr${NC}"
                    fi
                fi
            done
        else
            echo -e "${YELLOW}Could not find system call table in /proc/kallsyms.${NC}"
        fi
    else
        echo -e "${YELLOW}Cannot check system call table - /proc/kallsyms not available.${NC}"
    fi
    
    # Alternative check using kprobes
    if command -v kprobe-tool &>/dev/null; then
        echo -e "${WHITE}Using kprobe to check system call integrity...${NC}"
        # This is a placeholder. In a real implementation, you'd use a tool like ftrace or systemtap.
    fi
    
    # 5. Look for common rootkit signatures
    echo -e "\n${YELLOW}[*] Looking for common rootkit signatures:${NC}"
    
    # Check for common backdoor ports
    rootkit_ports=("1524" "2001" "4156" "5505" "13373" "31337" "33334" "47107" "60922")
    
    echo -e "${WHITE}Checking for common backdoor ports:${NC}"
    for port in "${rootkit_ports[@]}"; do
        if ss -tuln | grep -q ":$port "; then
            echo -e "${RED}Potential rootkit backdoor port found: $port${NC}"
            ss -tuln | grep ":$port "
        fi
    done
    
    # Check for common rootkit strings in binaries
    echo -e "\n${WHITE}Checking binaries for common rootkit strings:${NC}"
    
    critical_binaries=("/bin/ls" "/bin/ps" "/bin/netstat" "/bin/ss" "/bin/ip" "/bin/df" "/bin/top" "/sbin/ifconfig" "/usr/bin/find" "/usr/bin/chsh" "/usr/bin/passwd")
    rootkit_strings=("adore" "diamorphine" "ipsuk" "knark" "rexedcs" "rkit" "ssniffer" "xC.o" "kkkhhhajn" "phalanx" "taskigt" "sshd22" "sneakin" "sn

# Function to check for suspicious cron jobs
check_cron_jobs() {
    echo -e "\n${CYAN}${BOLD}[+] Checking cron jobs...${NC}"
    
    # Helper function to analyze cron content for suspicious commands
    analyze_cron_content() {
        local content="$1"
        local source="$2"
        
        # Check for suspicious commands in cron content
        if echo "$content" | grep -qiE '(wget|curl|nc|netcat|bash.*http|python.*http|perl.*http|\beval\b|\bbase64\b|\/dev\/shm|\/dev\/null.*2\>&1|\&\>\/dev\/null|0\.0\.0\.0|\$\(\(|\`\`|chmod \+x|chmod 777|mkfifo|mknod|telnet|ncat|socat|\.bashrc|\bperl -e\b|\bruby -e\b|\/tmp\/|\/var\/tmp|\bnohup\b|\bxterm\b|tor2web|\.onion|torsocks)'; then
            echo -e "${RED}Suspicious commands found in $source:${NC}"
            echo "$content" | grep -iE '(wget|curl|nc|netcat|bash.*http|python.*http|perl.*http|\beval\b|\bbase64\b|\/dev\/shm|\/dev\/null.*2\>&1|\&\>\/dev\/null|0\.0\.0\.0|\$\(\(|\`\`|chmod \+x|chmod 777|mkfifo|mknod|telnet|ncat|socat|\.bashrc|\bperl -e\b|\bruby -e\b|\/tmp\/|\/var\/tmp|\bnohup\b|\bxterm\b|tor2web|\.onion|torsocks)' | sed 's/^/  /'
            return 1
        fi
        
        # Check for obfuscation patterns
        if echo "$content" | grep -qE '`(base64|gzip|bzip2|hexdump|xxd|od|tr|sed) -'; then
            echo -e "${RED}Obfuscated commands found in $source:${NC}"
            echo "$content" | grep -E '`(base64|gzip|bzip2|hexdump|xxd|od|tr|sed) -' | sed 's/^/  /'
            return 1
        fi
        
        # Check for reverse shells
        if echo "$content" | grep -qE '(bash -i|\/bin\/bash -i|sh -i|\/dev\/tcp|\/dev\/udp|fsockopen|awk.*\/inet\/tcp|python.*socket\.socket|ruby.*TCPSocket|perl.*socket|nc -e|netcat -e|mkfifo.*\/bin\/sh|\$\{IFS\})'; then
            echo -e "${RED}Potential reverse shell found in $source:${NC}"
            echo "$content" | grep -E '(bash -i|\/bin\/bash -i|sh -i|\/dev\/tcp|\/dev\/udp|fsockopen|awk.*\/inet\/tcp|python.*socket\.socket|ruby.*TCPSocket|perl.*socket|nc -e|netcat -e|mkfifo.*\/bin\/sh|\$\{IFS\})' | sed 's/^/  /'
            return 1
        fi
        
        return 0
    }
    
    # Helper function to check file permissions
    check_cron_permissions() {
        local file="$1"
        local owner=$(stat -c "%U" "$file" 2>/dev/null)
        local group=$(stat -c "%G" "$file" 2>/dev/null)
        local perms=$(stat -c "%a" "$file" 2>/dev/null)
        
        # Check ownership (should be root or specific system user for system crontabs)
        if [[ "$file" == "/etc/crontab" || "$file" =~ /etc/cron\. ]] && [[ "$owner" != "root" ]]; then
            echo -e "${RED}Warning: $file has incorrect ownership: $owner:$group (should be root)${NC}"
            return 1
        fi
        
        # Check permissions (should not be world-writable)
        if [[ "$perms" =~ [2-7]$ ]]; then
            echo -e "${RED}Warning: $file has incorrect permissions: $perms (world-writable)${NC}"
            return 1
        fi
        
        # For user crontabs in /var/spool/cron/crontabs, they should be owned by the user
        if [[ "$file" =~ /var/spool/cron/crontabs/ ]]; then
            local username=$(basename "$file")
            if [[ "$owner" != "$username" && "$owner" != "root" ]]; then
                echo -e "${RED}Warning: User crontab $file has incorrect ownership: $owner (should be $username or root)${NC}"
                return 1
            fi
        fi
        
        return 0
    }

    # 1. Check system-wide cron directories and crontabs
    echo -e "\n${YELLOW}[*] Checking system-wide cron directories and crontabs:${NC}"
    
    # Check /etc/crontab
    if [ -f "/etc/crontab" ]; then
        echo -e "${WHITE}Analyzing /etc/crontab:${NC}"
        check_cron_permissions "/etc/crontab"
        analyze_cron_content "$(cat /etc/crontab)" "/etc/crontab"
    else
        echo -e "${YELLOW}No /etc/crontab found.${NC}"
    fi
    
    # Check /etc/cron.d directory
    if [ -d "/etc/cron.d" ]; then
        echo -e "\n${WHITE}Analyzing /etc/cron.d directory:${NC}"
        find /etc/cron.d -type f -not -name ".*" | while read cronfile; do
            echo -e "${WHITE}Checking $cronfile:${NC}"
            check_cron_permissions "$cronfile"
            analyze_cron_content "$(cat $cronfile 2>/dev/null)" "$cronfile"
        done
    fi
    
    # Check periodic cron directories
    for crondir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        if [ -d "$crondir" ]; then
            echo -e "\n${WHITE}Analyzing $crondir directory:${NC}"
            find "$crondir" -type f -not -name ".*" | while read scriptfile; do
                echo -e "${WHITE}Checking $scriptfile:${NC}"
                check_cron_permissions "$scriptfile"
                
                # Check if the file is executable
                if [ ! -x "$scriptfile" ]; then
                    echo -e "${YELLOW}Warning: $scriptfile is not executable. It may not run as expected.${NC}"
                fi
                
                # Analyze the script's content
                analyze_cron_content "$(cat $scriptfile 2>/dev/null)" "$scriptfile"
            done
        fi
    done
    
    # 2. Scan user crontabs
    echo -e "\n${YELLOW}[*] Scanning user crontabs:${NC}"
    
    # Check for crontab directories
    if [ -d "/var/spool/cron/crontabs" ]; then
        echo -e "${WHITE}Analyzing user crontabs in /var/spool/cron/crontabs:${NC}"
        find /var/spool/cron/crontabs -type f | while read usercron; do
            username=$(basename "$usercron")
            echo -e "${WHITE}Checking crontab for user $username:${NC}"
            check_cron_permissions "$usercron"
            analyze_cron_content "$(cat $usercron 2>/dev/null)" "crontab for $username"
        done
    elif [ -d "/var/spool/cron" ]; then
        echo -e "${WHITE}Analyzing user crontabs in /var/spool/cron:${NC}"
        find /var/spool/cron -type f | while read usercron; do
            username=$(basename "$usercron")
            echo -e "${WHITE}Checking crontab for user $username:${NC}"
            check_cron_permissions "$usercron"
            analyze_cron_content "$(cat $usercron 2>/dev/null)" "crontab for $username"
        done
    else
        echo -e "${YELLOW}No user crontab directory found.${NC}"
    fi
    
    # 3 & 4. Check for hidden or unauthorized cron jobs
    echo -e "\n${YELLOW}[*] Checking for hidden or unauthorized cron jobs:${NC}"
    
    # Look for hidden files in cron directories
    for crondir in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron/crontabs /var/spool/cron; do
        if [ -d "$crondir" ]; then
            hidden_files=$(find "$crondir" -name ".*" -type f 2>/dev/null)
            if [ -n "$hidden_files" ]; then
                echo -e "${RED}Hidden files found in $crondir:${NC}"
                echo "$hidden_files" | while read hidden_file; do
                    echo -e "  $hidden_file ($(stat -c '%U:%G %a' "$hidden_file"))"
                    analyze_cron_content "$(cat $hidden_file 2>/dev/null)" "$hidden_file"
                done
            fi
        fi
    done
    
    # Check for crontabs for system users or users that shouldn't have cron jobs
    system_users_with_cron=0
    for user in bin daemon adm lp sync shutdown halt mail news uucp operator games nobody; do
        if [ -f "/var/spool/cron/crontabs/$user" ] || [ -f "/var/spool/cron/$user" ]; then
            echo -e "${RED}System user $user has a crontab!${NC}"
            system_users_with_cron=1
        fi
    done
    
    if [ $system_users_with_cron -eq 0 ]; then
        echo -e "${GREEN}No crontabs found for system users.${NC}"
    fi
    
    # 5. Cross-check with running cron processes
    echo -e "\n${YELLOW}[*] Cross-checking with running cron processes:${NC}"
    
    # Get running cron processes
    cron_procs=$(ps aux | grep -E '(cron|crond)' | grep -v grep)
    if [ -n "$cron_procs" ]; then
        echo -e "${WHITE}Running cron processes:${NC}"
        echo "$cron_procs"
        
        # Check if cron is using unusual arguments
        unusual_args=$(echo "$cron_procs" | grep -vE '(cron|crond)( -f| -l)?$')
        if [ -n "$unusual_args" ]; then
            echo -e "${RED}Cron processes with unusual arguments:${NC}"
            echo "$unusual_args"
        fi
    else
        echo -e "${YELLOW}Warning: No cron processes found running!${NC}"
    fi
    
    # Additional check: Try to list all crontabs if crontab command is available
    if command -v crontab &> /dev/null; then
        echo -e "\n${YELLOW}[*] Listing all users with crontabs using 'crontab -l':${NC}"
        
        # Get all users
        users=$(cut -d: -f1 /etc/passwd)
        
        crontab_users=0
        for user in $users; do
            # Skip system users with UID < a specific threshold
            uid=$(id -u $user 2>/dev/null || echo "0")
            if [ "$uid" -lt 1000 ] && [ "$user" != "root" ]; then
                continue
            fi
            
            crontab_output=$(su - "$user" -c "crontab -l" 2>/dev/null)
            if [ $? -eq 0 ] && [ -n "$crontab_output" ]; then
                echo -e "${WHITE}User $user has the following crontab entries:${NC}"
                echo "$crontab_output" | sed 's/^/  /'
                analyze_cron_content "$crontab_output" "crontab for $user"
                crontab_users=1
            fi
        done
        
        if [ $crontab_users -eq 0 ]; then
            echo -e "${GREEN}No user crontabs found via 'crontab -l'.${NC}"
        fi
    fi
    
    # Look for anacron jobs
    if [ -f "/etc/anacrontab" ]; then
        echo -e "\n${YELLOW}[*] Checking anacron jobs:${NC}"
        echo -e "${WHITE}Analyzing /etc/anacrontab:${NC}"
        check_cron_permissions "/etc/anacrontab"
        analyze_cron_content "$(cat /etc/anacrontab 2>/dev/null)" "/etc/anacrontab"
    fi
    
    # Additional: Check systemd timer units that may be used instead of cron
    if command -v systemctl &> /dev/null; then
        echo -e "\n${YELLOW}[*] Checking systemd timer units (modern alternative to cron):${NC}"
        timer_units=$(systemctl list-timers --all 2>/dev/null)
        if [ -n "$timer_units" ]; then
            echo -e "${WHITE}Active systemd timers:${NC}"
            echo "$timer_units" | head -n 20
            
            # Count total timers
            timer_count=$(echo "$timer_units" | grep -c ".timer")
            if [ "$timer_count" -gt 20 ]; then
                echo -e "... and $((timer_count - 20)) more timers (total: $timer_count)"
            fi
            
            # Check for suspicious timer units
            suspicious_units=$(systemctl list-unit-files --type=timer | grep -vE '(apt-daily|logrotate|man-db|fstrim|shadow|motd|e2scrub|btrfs|snapper|dnf|packagekit|certbot|backup)')
            if [ -n "$suspicious_units" ]; then
                echo -e "\n${YELLOW}Potentially unusual timer units:${NC}"
                echo "$suspicious_units"
                
                # Get the actual service files for suspicious timers
                echo "$suspicious_units" | grep -v "timer units listed" | awk '{print $1}' | while read timer_unit; do
                    unit_name=${timer_unit%.timer}.service
                    echo -e "\n${WHITE}Checking service for timer $timer_unit:${NC}"
                    if systemctl cat "$unit_name" &>/dev/null; then
                        service_content=$(systemctl cat "$unit_name" 2>/dev/null)
                        echo "$service_content" | grep -E '(ExecStart|

# Function to check for suspicious SUID/SGID files
check_suid_sgid() {
    echo -e "\n${CYAN}${BOLD}[+] Checking for suspicious SUID/SGID binaries...${NC}"
    
    # Helper function to check if a binary is in the whitelist
    is_in_whitelist() {
        local binary="$1"
        local binary_name=$(basename "$binary")
        
        # Define whitelist of known legitimate SUID/SGID binaries
        local suid_whitelist=(
            # Standard system binaries that commonly have SUID bit
            "su" "sudo" "newgrp" "passwd" "gpasswd" "chsh" "chfn"
            "mount" "umount" "fusermount" "pkexec" "polkit-agent-helper-1"
            "dbus-daemon-launch-helper" "exim4" "chage" "at" "crontab"
            "ping" "ping6" "traceroute6.iputils" "pppd" "ssh-agent"
            "dotlockfile" "Xorg" "Xorg.wrap" "ntfs-3g" "arnesi"
            # Common legitimate SUID root programs
            "arping" "ksu" "kpac_dhcp_helper" "helper" "unix_chkpwd"
            "mtr" "screen" "bwrap" "pam_timestamp_check" "suexec"
            "checkpoint" "authorizecheckd" "authopen" "traceroute"
            "pt_chown" "staprun" "crontab" "stunnel4" "exim4"
            "uuidd" "ppp" "locate" "lockfile" "mutt_dotlock" "dictzip"
        )
        
        for whitelist_binary in "${suid_whitelist[@]}"; do
            if [[ "$binary_name" == "$whitelist_binary" ]]; then
                return 0  # Binary is in whitelist
            fi
        done
        
        # Check common directories for legitimate SUID binaries
        local legitimate_dirs=(
            "/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin"
            "/lib" "/lib64" "/usr/lib" "/usr/lib64" "/usr/libexec"
        )
        
        # If binary is in legitimate directory and not obviously suspicious, consider it potentially legitimate
        for legit_dir in "${legitimate_dirs[@]}"; do
            if [[ "$binary" == "$legit_dir"/* ]]; then
                # This is not a guarantee it's safe, but it's in a standard system directory
                return 2  # Potentially legitimate location
            fi
        done
        
        return 1  # Not in whitelist
    }
    
    # Helper function to check binary file properties and detect anomalies
    analyze_binary() {
        local binary="$1"
        local binary_name=$(basename "$binary")
        local result=0
        
        # Check if file exists and is readable
        if [ ! -r "$binary" ]; then
            echo -e "${RED}Warning: Cannot read binary for analysis: $binary${NC}"
            return 1
        fi
        
        # Check file type to ensure it's actually an executable
        local file_type=$(file "$binary" 2>/dev/null)
        if ! echo "$file_type" | grep -qE '(executable|ELF|PE32|Mach-O)'; then
            echo -e "${RED}Warning: SUID/SGID file is not an executable: $binary${NC}"
            echo -e "  File type: $file_type"
            result=1
        fi
        
        # Check for suspicious strings in the binary
        local suspicious_strings=$(strings "$binary" 2>/dev/null | grep -iE '(bash|sh |-i|/dev/(tcp|udp)|socket|connect|bind|listen|accept|python|perl|ruby|nc |netcat|curl|wget|chmod( |\+x)|eval|system|popen|exec|spawn|fork|pcap|tcpdump|rawsocket|libpcap|sniff)')
        if [ -n "$suspicious_strings" ]; then
            echo -e "${RED}Suspicious strings found in binary:${NC}"
            echo "$suspicious_strings" | head -n 10 | sed 's/^/  /'
            
            # Show count if there are many matches
            local count=$(echo "$suspicious_strings" | wc -l)
            if [ $count -gt 10 ]; then
                echo -e "  ... and $((count - 10)) more suspicious strings"
            fi
            result=1
        fi
        
        # Check for suspicious imported libraries and functions
        if command -v objdump &>/dev/null; then
            local imports=$(objdump -T "$binary" 2>/dev/null | grep FUNC | grep -iE '(system|exec|popen|fork|socket|connect|listen|accept|setuid|setgid)')
            if [ -n "$imports" ]; then
                echo -e "${RED}Suspicious imported functions:${NC}"
                echo "$imports" | head -n 10 | sed 's/^/  /'
                result=1
            fi
        fi
        
        # Check for suspicious shared libraries using ldd
        if command -v ldd &>/dev/null; then
            local suspicious_libs=$(ldd "$binary" 2>/dev/null | grep -E '(/tmp|/dev/shm|/var/tmp|not found)')
            if [ -n "$suspicious_libs" ]; then
                echo -e "${RED}Suspicious shared libraries:${NC}"
                echo "$suspicious_libs" | sed 's/^/  /'
                result=1
            fi
        fi
        
        # Check if the file was recently modified or has unusual timestamps
        local modify_time=$(stat -c %Y "$binary" 2>/dev/null)
        local current_time=$(date +%s)
        
        # Check for files modified within the last 30 days
        if (( current_time - modify_time < 2592000 )); then # 30 days in seconds
            echo -e "${YELLOW}Binary was recently modified:${NC}"
            echo -e "  Last modified: $(stat -c '%y' "$binary")"
            result=1
        fi
        
        # Check for unusual access vs modify timestamps (indicates potential tampering)
        local access_time=$(stat -c %X "$binary" 2>/dev/null)
        local change_time=$(stat -c %Z "$binary" 2>/dev/null)
        
        # If change time is much newer than modify time, it might indicate metadata tampering
        if (( change_time - modify_time > 86400 )); then # More than 1 day difference
            echo -e "${RED}Suspicious timestamp anomaly:${NC}"
            echo -e "  Modified: $(stat -c '%y' "$binary")"
            echo -e "  Metadata changed: $(stat -c '%z' "$binary")"
            result=1
        fi
        
        # Additional check for binaries in world-writable directories
        local parent_dir=$(dirname "$binary")
        local dir_perms=$(stat -c "%a" "$parent_dir" 2>/dev/null)
        if [[ "$dir_perms" =~ [2-7]$ ]]; then
            echo -e "${RED}Binary is in a world-writable directory:${NC}"
            echo -e "  Directory: $parent_dir (permissions: $dir_perms)"
            result=1
        fi
        
        return $result
    }
    
    # Helper function to check file hash against known malicious hashes
    # This is a placeholder - in a real implementation, you'd have a database of known malicious hashes
    check_hash_blacklist() {
        local binary="$1"
        local file_hash=$(sha256sum "$binary" 2>/dev/null | awk '{print $1}')
        
        # In a real implementation, compare against a database of known malicious SUID/SGID binaries
        # For this script, just return the hash for informational purposes
        echo "$file_hash"
        return 0
    }
    
    # 1. Find and analyze all SUID/SGID binaries
    echo -e "\n${YELLOW}[*] Searching for SUID/SGID binaries on the system:${NC}"
    
    # Create temporary files for output
    local suid_files=$(mktemp)
    local sgid_files=$(mktemp)
    
    echo -e "${WHITE}This may take a while on large systems...${NC}"
    
    # Find all SUID files
    find / -type f -perm -4000 -not -path "/proc/*" -not -path "/sys/*" -not -path "/run/*" 2>/dev/null > "$suid_files"
    
    # Find all SGID files
    find / -type f -perm -2000 -not -path "/proc/*" -not -path "/sys/*" -not -path "/run/*" 2>/dev/null > "$sgid_files"
    
    echo -e "${GREEN}Found $(wc -l < "$suid_files") SUID binaries and $(wc -l < "$sgid_files") SGID binaries${NC}"
    
    # 2. Compare against whitelist and check for unusual locations
    echo -e "\n${YELLOW}[*] Analyzing SUID binaries:${NC}"
    
    # Process SUID files
    if [ -s "$suid_files" ]; then
        while read binary; do
            is_in_whitelist "$binary"
            whitelist_status=$?
            
            if [ $whitelist_status -eq 1 ]; then
                # Not in whitelist - suspicious
                echo -e "${RED}Potentially suspicious SUID binary:${NC} $binary"
                echo -e "  Owner: $(stat -c '%U:%G' "$binary")"
                echo -e "  Permissions: $(stat -c '%A' "$binary")"
                
                # 3 & 4. Analyze file properties and content
                analyze_binary "$binary"
            elif [ $whitelist_status -eq 2 ]; then
                # In legitimate directory but not in whitelist
                echo -e "${YELLOW}Uncommon SUID binary in standard location:${NC} $binary"
                echo -e "  Owner: $(stat -c '%U:%G' "$binary")"
                echo -e "  Permissions: $(stat -c '%A' "$binary")"
                
                # Less aggressive analysis for potentially legitimate binaries
                if analyze_binary "$binary"; then
                    echo -e "${GREEN}No suspicious indicators found in this binary${NC}"
                fi
            else
                # Known legitimate binary - basic logging
                echo -e "${GREEN}Known legitimate SUID binary:${NC} $binary"
            fi
        done < "$suid_files"
    fi
    
    # Process SGID files
    echo -e "\n${YELLOW}[*] Analyzing SGID binaries:${NC}"
    
    if [ -s "$sgid_files" ]; then
        while read binary; do
            is_in_whitelist "$binary"
            whitelist_status=$?
            
            if [ $whitelist_status -eq 1 ]; then
                # Not in whitelist - suspicious
                echo -e "${RED}Potentially suspicious SGID binary:${NC} $binary"
                echo -e "  Owner: $(stat -c '%U:%G' "$binary")"
                echo -e "  Permissions: $(stat -c '%A' "$binary")"
                
                # 3 & 4. Analyze file properties and content
                analyze_binary "$binary"
            elif [ $whitelist_status -eq 2 ]; then
                # In legitimate directory but not in whitelist
                echo -e "${YELLOW}Uncommon SGID binary in standard location:${NC} $binary"
                echo -e "  Owner: $(stat -c '%U:%G' "$binary")"
                echo -e "  Permissions: $(stat -c '%A' "$binary")"
                
                # Less aggressive analysis for potentially legitimate binaries
                if analyze_binary "$binary"; then
                    echo -e "${GREEN}No suspicious indicators found in this binary${NC}"
                fi
            else
                # Known legitimate binary - basic logging
                echo -e "${GREEN}Known legitimate SGID binary:${NC} $binary"
            fi
        done < "$sgid_files"
    fi
    
    # 5. Check for unusual locations of SUID/SGID binaries
    echo -e "\n${YELLOW}[*] Checking for SUID/SGID binaries in unusual locations:${NC}"
    
    # Directories that are unusual for SUID/SGID binaries
    unusual_dirs=(
        "/tmp" "/var/tmp" "/dev/shm" "/home" "/var/www"
        "/var/spool" "/usr/local/src" "/opt" "/srv"
        "/var/mail" "/var/log" "/var/crash" "/mnt" "/media"
    )
    
    for dir in "${unusual_dirs[@]}"; do
        if [ -d "$dir" ]; then
            unusual_binaries=$(find "$dir" -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
            if [ -n "$unusual_binaries" ]; then
                echo -e "${RED}SUID/SGID binaries found in unusual location:${NC} $dir"
                echo "$unusual_binaries" | while read binary; do
                    echo -e "  $binary ($(stat -c '%U:%G %A' "$binary"))"
                    analyze_binary "$binary"
                done
            fi
        fi
    done
    
    # Check for SUID/SGID binaries owned by non-root users
    echo -e "\n${YELLOW}[*] Checking for SUID/SGID binaries owned by non-root users:${NC}"
    
    non_root_binaries=$(find / -type f \( -perm -4000 -o -perm -2000 \) -not -user root -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null)
    if [ -n "$non_root_binaries" ]; then
        echo -e "${RED}SUID/SGID binaries found with non-root ownership:${NC}"
        echo "$non_root_binaries" | while read binary; do
            echo -e "  $binary ($(stat -c '%U:%G %A' "$binary"))"
            analyze_binary "$binary"
        done
    else
        echo -e "${GREEN}No SUID/SGID binaries with non-root ownership found.${NC}"
    fi
    
    # Final checks: SUID shell scripts (extremely suspicious)
    echo -e "\n${YELLOW}[*] Checking for SUID/SGID shell scripts (high risk):${NC}"
    
    shell_scripts=$(cat "$suid_files" "$sgid_files" | xargs -I {} file {} 2>/dev/null | grep -E "shell

# Function to analyze system logs
check_logs() {
    echo -e "\n${CYAN}${BOLD}[+] Analyzing system logs for suspicious activity...${NC}"
    
    # Helper function to check authentication logs for suspicious patterns
    check_auth_logs() {
        echo -e "\n${YELLOW}[*] Checking authentication logs for suspicious login patterns:${NC}"
        
        # Define auth log files based on distro
        auth_logs=()
        [ -f "/var/log/auth.log" ] && auth_logs+=("/var/log/auth.log")
        [ -f "/var/log/secure" ] && auth_logs+=("/var/log/secure")
        [ -f "/var/log/audit/audit.log" ] && auth_logs+=("/var/log/audit/audit.log")
        
        if [ ${#auth_logs[@]} -eq 0 ]; then
            echo -e "${YELLOW}No authentication log files found or accessible.${NC}"
            return
        fi
        
        # Check for failed login attempts
        for log_file in "${auth_logs[@]}"; do
            echo -e "${WHITE}Analyzing $log_file:${NC}"
            
            # Check for brute force attempts (many failed logins)
            failed_logins=$(grep -i "failed\|failure\|invalid" "$log_file" 2>/dev/null)
            if [ -n "$failed_logins" ]; then
                failed_count=$(echo "$failed_logins" | wc -l)
                echo -e "${YELLOW}Found $failed_count failed login attempts${NC}"
                
                # Count failed attempts by IP/user
                echo -e "${WHITE}Top sources of failed logins:${NC}"
                echo "$failed_logins" | grep -oE "from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort | uniq -c | sort -nr | head -n 10 || true
                echo "$failed_logins" | grep -oE "user [a-zA-Z0-9_-]+" | sort | uniq -c | sort -nr | head -n 10 || true
                
                # Show recent failed login attempts
                echo -e "\n${WHITE}Recent failed login attempts:${NC}"
                echo "$failed_logins" | tail -n 10
            else
                echo -e "${GREEN}No failed login attempts found.${NC}"
            fi
            
            # Check for successful logins outside normal hours (e.g. 11PM-5AM)
            echo -e "\n${WHITE}Checking for off-hours successful logins:${NC}"
            off_hours_logins=$(grep -i "session opened\|accepted\|success" "$log_file" 2>/dev/null | grep -E "([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]" | grep -E "(2[3]|[01][0-9]|2[0-2]):[0-5][0-9]:[0-5][0-9]" | grep -v "localhost")
            if [ -n "$off_hours_logins" ]; then
                echo -e "${YELLOW}Found logins during off-hours:${NC}"
                echo "$off_hours_logins" | tail -n 10
            else
                echo -e "${GREEN}No suspicious off-hours logins detected.${NC}"
            fi
            
            # Check for root logins
            echo -e "\n${WHITE}Checking for root logins:${NC}"
            root_logins=$(grep -i "root" "$log_file" 2>/dev/null | grep -i "session opened\|accepted\|success")
            if [ -n "$root_logins" ]; then
                echo -e "${RED}Found direct root logins:${NC}"
                echo "$root_logins" | tail -n 10
            else
                echo -e "${GREEN}No direct root logins detected.${NC}"
            fi
            
            # Check for unusual user logins
            echo -e "\n${WHITE}Checking for logins from unusual users:${NC}"
            unusual_users="daemon bin sys games man lp mail news uucp proxy www-data backup list irc gnats nobody systemd-network systemd-resolve sshd"
            unusual_logins=$(grep -i "session opened\|accepted\|success" "$log_file" 2>/dev/null)
            for user in $unusual_users; do
                user_logins=$(echo "$unusual_logins" | grep -i "for $user\|user=$user\|user $user")
                if [ -n "$user_logins" ]; then
                    echo -e "${RED}Found logins from system user $user:${NC}"
                    echo "$user_logins" | tail -n 5
                fi
            done
            
            # Check for SSH logins from unusual IP addresses or domains
            echo -e "\n${WHITE}Checking for logins from unusual sources:${NC}"
            
            # Define private IP ranges to exclude
            private_ips="(^127\.|^10\.|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-1]\.|^192\.168\.)"
            
            # Find non-private IPs
            external_logins=$(grep -i "session opened\|accepted\|success" "$log_file" 2>/dev/null | grep -oE "from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | grep -vE "$private_ips" || true)
            
            if [ -n "$external_logins" ]; then
                echo -e "${RED}Found logins from external IP addresses:${NC}"
                echo "$external_logins" | sort | uniq -c | sort -nr
            else
                echo -e "${GREEN}No logins from external IP addresses.${NC}"
            fi
        done
    }
    
    # Helper function to analyze system logs for security events
    check_system_logs() {
        echo -e "\n${YELLOW}[*] Analyzing system logs for security events:${NC}"
        
        # Common system log files
        system_logs=()
        [ -f "/var/log/syslog" ] && system_logs+=("/var/log/syslog")
        [ -f "/var/log/messages" ] && system_logs+=("/var/log/messages")
        [ -f "/var/log/kern.log" ] && system_logs+=("/var/log/kern.log")
        [ -f "/var/log/dmesg" ] && system_logs+=("/var/log/dmesg")
        
        if [ ${#system_logs[@]} -eq 0 ]; then
            echo -e "${YELLOW}No system log files found or accessible.${NC}"
            return
        fi
        
        # Define security-related keywords to search for
        security_keywords=(
            "denied" "error" "warning" "fail" "failure" "attack" "suspect" 
            "intrusion" "firewall" "permission" "unauthorized" "authentication"
            "illegal" "invalid" "exploit" "vulnerability" "crash" "segfault"
            "violation" "unable" "refused" "rejected" "rootkit" "hack"
            "trojan" "malicious" "malware" "virus" "ransom" "backdoor"
            "overflow" "race condition" "injection" "dos" "ddos" "bruteforce"
        )
        
        # Combine keywords into a grep pattern
        pattern=$(IFS="|"; echo "${security_keywords[*]}")
        
        for log_file in "${system_logs[@]}"; do
            echo -e "\n${WHITE}Analyzing $log_file for security-related events:${NC}"
            
            # Check for security-related events
            security_events=$(grep -iE "$pattern" "$log_file" 2>/dev/null | grep -v "grep" | tail -n 50)
            
            if [ -n "$security_events" ]; then
                event_count=$(echo "$security_events" | wc -l)
                echo -e "${YELLOW}Found $event_count potential security-related events. Showing latest entries:${NC}"
                echo "$security_events" | tail -n 20
            else
                echo -e "${GREEN}No obvious security-related events found.${NC}"
            fi
            
            # Check for unexpected system shutdowns or reboots
            echo -e "\n${WHITE}Checking for unexpected system shutdowns or reboots:${NC}"
            shutdown_events=$(grep -iE "(shutdown|reboot|halt|power.*down)" "$log_file" 2>/dev/null | tail -n 10)
            
            if [ -n "$shutdown_events" ]; then
                echo -e "${YELLOW}Recent system shutdown/reboot events:${NC}"
                echo "$shutdown_events"
            fi
            
            # Check for kernel oops, panic or hardware errors
            echo -e "\n${WHITE}Checking for kernel issues or hardware errors:${NC}"
            kernel_issues=$(grep -iE "(oops|panic|hardware error|I/O error|soft lockup|hung task|general protection fault)" "$log_file" 2>/dev/null)
            
            if [ -n "$kernel_issues" ]; then
                echo -e "${RED}Found kernel issues or hardware errors:${NC}"
                echo "$kernel_issues" | tail -n 15
            else
                echo -e "${GREEN}No kernel issues or hardware errors detected.${NC}"
            fi
            
            # Check for disk space issues
            echo -e "\n${WHITE}Checking for disk space issues:${NC}"
            disk_issues=$(grep -iE "(no space left|disk full|filesystem full)" "$log_file" 2>/dev/null)
            
            if [ -n "$disk_issues" ]; then
                echo -e "${RED}Found disk space issues:${NC}"
                echo "$disk_issues" | tail -n 10
            else
                echo -e "${GREEN}No disk space issues detected in logs.${NC}"
            fi
        done
    }
    
    # Helper function to review bash history for suspicious commands
    check_bash_history() {
        echo -e "\n${YELLOW}[*] Reviewing bash history for suspicious commands:${NC}"
        
        # Get list of users with home directories
        users_with_home=$(ls -la /home 2>/dev/null | grep -E '^d' | awk '{print $3}' | grep -v 'root')
        users_with_home="$users_with_home root"  # Also check root's history
        
        # Define suspicious command patterns
        suspicious_commands=(
            # Data exfiltration and network commands
            "wget" "curl" "nc " "netcat" "ftp" "sftp" "ssh" "scp" "rsync" "telnet"
            # Backdoors and reverse shells
            "bash -i" "sh -i" "/bin/bash -i" "/dev/tcp/" "/dev/udp/"
            "python.*socket" "perl.*socket" "ruby.*socket" "php.*socket"
            # Tampering with logs
            "rm .*log" "echo.*>/var/log" ">/var/log/" "truncate.*log"
            # Encoding/obfuscation
            "base64" "eval" "gzip" "bzip2" "zip" "tar" "uuencode" "xxd"
            # Privilege escalation attempts
            "sudo" "su" "chmod.*777" "chmod.*u+s" "visudo" "usermod" "chown"
            # Unusual file operations
            "dd " "shred" "mkfifo" "mknod" "touch -r" 
            # Access to sensitive areas
            "cat .*shadow" "cat .*passwd" "vim .*shadow" "vim .*passwd"
            # Process hiding
            "kill -9" "pkill" "ps aux" "top"
            # Persistence
            "crontab" "at " "systemctl" "service" "insmod" "modprobe"
            # Scanning tools
            "nmap" "masscan" "nikto" "sqlmap" "hydra" "dirb"
            # Compiling
            "gcc" "g++" "make" "ld" "clang"
        )
        
        # Combine patterns
        cmd_pattern=$(IFS="|"; echo "${suspicious_commands[*]}")
        
        found_suspicious=0
        
        for user in $users_with_home; do
            # Determine history file path
            if [ "$user" = "root" ]; then
                history_file="/root/.bash_history"
            else
                history_file="/home/$user/.bash_history"
            fi
            
                echo -e "\n${WHITE}Analyzing bash history for user $user:${NC}"
                
                # Search for suspicious commands in history
                suspicious_history=$(grep -iE "$cmd_pattern" "$history_file" 2>/dev/null)
                
                if [ -n "$suspicious_history" ]; then
                    count=$(echo "$suspicious_history" | wc -l)
                    echo -e "${YELLOW}Found $count potentially suspicious commands in $user's history:${NC}"
                    
                    # Display the suspicious commands with categorization
                    if echo "$suspicious_history" | grep -qiE "(wget|curl|nc |netcat|ftp|sftp|ssh|scp|rsync|telnet)"; then
                        echo -e "${RED}Network/Download commands:${NC}"
                        echo "$suspicious_history" | grep -iE "(wget|curl|nc |netcat|ftp|sftp|ssh|scp|rsync|telnet)" | tail -n 10
                    fi
                    
                    if echo "$suspicious_history" | grep -qiE "(bash -i|sh -i|/bin/bash -i|/dev/tcp/|/dev/udp/|python.*socket|perl.*socket|ruby.*socket|php.*socket)"; then
                        echo -e "${RED}Potential backdoor/shell commands:${NC}"
                        echo "$suspicious_history" | grep -iE "(bash -i|sh -i|/bin/bash -i|/dev/tcp/|/dev/udp/|python.*socket|perl.*socket|ruby.*socket|php.*socket)" | tail -n 10
                    fi
                    
                    if echo "$suspicious_history" | grep -qiE "(rm .*log|echo.*>/var/log|>/var/log/|truncate.*log)"; then
                        echo -e "${RED}Log tampering commands:${NC}"
                        echo "$suspicious_history" | grep -iE "(rm .*log|echo.*>/var/log|>/var/log/|truncate.*log)" | tail -n 10
                    fi
                    
                    if echo "$suspicious_history" | grep -qiE "(base64|eval|gzip|bzip2|zip|tar|uuencode|xxd)"; then
                        echo -e "${YELLOW}Encoding/Compression commands:${NC}"
                        echo "$suspicious_history" | grep -iE "(base64|eval|gzip|bzip2|zip|tar|uuencode|xxd)" | tail -n 10
                    fi
                    
                    if echo "$suspicious_history" | grep -qiE "(chmod.*777|chmod.*u\+s|chown)"; then
                        echo -e "${RED}Suspicious permission changes:${NC}"
                        echo "$suspicious_history" | grep -iE "(chmod.*777|chmod.*u\+s|chown)" | tail -n 10
                    fi
                    
                    if echo "$suspicious_history" | grep -qiE "(gcc|g\+\+|make|ld|clang)"; then
                        echo -e "${YELLOW}Compilation commands:${NC}"
                        echo "$suspicious_history" | grep -iE "(gcc|g\+\+|make|ld|clang)" | tail -n 10
                    fi
                    
                    found_suspicious=1
                else
                    echo -e "${GREEN}No suspicious commands found in $user's bash history.${NC}"
                fi
            else
                # History file not found or not readable
                if [ "$user" != "root" ] || [ $(id -u) -eq 0 ]; then  # Don't warn about root's history if we're not root
                    echo -e "${YELLOW}Could not read bash history for user $user.${NC}"
                fi
            fi
        done
        
        if [ $found_suspicious -eq 0 ]; then
            echo -e "${GREEN}No suspicious commands found in any user's bash history.${NC}"
        fi
        
        # Check for deleted bash history files
        echo -e "\n${WHITE}Checking for potential bash history tampering:${NC}"
        for user in $users_with_home; do
            if [ "$user" = "root" ]; then
                history_file="/root/.bash_history"
            else
                history_file="/home/$user/.bash_history"
            fi
            
            if [ -f "$history_file" ]; then
                # Check file size
                size=$(du -b "$history_file" 2>/dev/null | awk '{print $1}')
                if [ "$size" -eq 0 ]; then
                    echo -e "${RED}Warning: $user's bash history file exists but is empty!${NC}"
                fi
            elif [ -d "$(dirname "$history_file")" ]; then
                # History file doesn't exist but home directory does
                echo -e "${RED}Warning: $user's bash history file is missing!${NC}"
            fi
        done
    }
    
    # Helper function to check audit logs for security events
    check_audit_logs() {
        echo -e "\n${YELLOW}[*] Analyzing audit logs for security events:${NC}"
        
        # Check if audit is enabled
        if ! command -v auditctl &> /dev/null; then
            echo -e "${YELLOW}Audit system (auditctl) not installed or not in PATH.${NC}"
            return
        fi
        
        # Check audit status
        echo -e "${WHITE}Current audit status:${NC}"
        auditctl -s 2>/dev/null || echo -e "${YELLOW}Could not get audit status.${NC}"
        
        # Check if audit logs exist
        audit_log="/var/log/audit/audit.log"
        if [ ! -f "$audit_log" ] || [ ! -r "$audit_log" ]; then
            echo -e "${YELLOW}Audit log file ($audit_log) not found or not readable.${NC}"
            return
        }
        
        echo -e "\n${WHITE}Analyzing audit logs for security events:${NC}"
        
        # Check for authentication failures
        echo -e "${WHITE}Authentication failures:${NC}"
        auth_failures=$(ausearch -m USER_AUTH -sv no 2>/dev/null || grep -i "authentication failure" "$audit_log" 2>/dev/null)
        if [ -n "$auth_failures" ]; then
            echo -e "${RED}Found authentication failures:${NC}"
            echo "$auth_failures" | tail -n 10
        else
            echo -e "${GREEN}No authentication failures found.${NC}"
        fi
        
        # Check for access denied events
        echo -e "\n${WHITE}Access denied events:${NC}"
        access_denied=$(ausearch -m USER_ACCT -sv no 2>/dev/null || grep -i "access denied" "$audit_log" 2>/dev/null)
        if [ -n "$access_denied" ]; then
            echo -e "${RED}Found access denied events:${NC}"
            echo "$access_denied" | tail -n 10
        else
            echo -e "${GREEN}No access denied events found.${NC}"
        fi
        
        # Check for privilege escalation
        echo -e "\n${WHITE}Privilege escalation events:${NC}"
        priv_esc=$(ausearch -m USER_START -su root 2>/dev/null || grep -i "user start.*uid=0" "$audit_log" 2>/dev/null)
        if [ -n "$priv_esc" ]; then
            echo -e "${YELLOW}Found privilege escalation to root:${NC}"
            echo "$priv_esc" | tail -n 10
        else
            echo -e "${GREEN}No privilege escalation events found.${NC}"
        fi
        
        # Check for time changes
        echo -e "\n${WHITE}System time change events:${NC}"
        time_changes=$(ausearch -m TIME_ADJTIME -m TIME_ADJTIME 2>/dev/null || grep -i "time" "$audit_log" | grep -i "change" 2>/dev/null)
        if [ -n "$time_changes" ]; then
            echo -e "${YELLOW}Found system time changes:${NC}"
            echo "$time_changes" | tail -n 10
        else
            echo -e "${GREEN}No system time changes found.${NC}"
        fi
        
        # Check for account modifications
        echo -e "\n${WHITE}Account modification events:${NC}"
        acct_changes=$(ausearch -m ADD_USER -m DEL_USER -m ROLE_ASSIGN -m ROLE_REMOVE 2>/dev/null || grep -iE "(add_user|del_user|change user|account changed)" "$audit_log" 2>/dev/null)
        if [ -n "$acct_changes" ]; then
            echo -e "${YELLOW}Found account modifications:${NC}"
            echo "$acct_changes" | tail -n 10
        else
            echo -e "${GREEN}No account modifications found.${NC}"
        fi
        
        # Check for suspicious executions
        echo -e "\n${WHITE}Suspicious command executions:${NC}"
        susp_execs=$(ausearch -m EXECVE 2>/dev/null | grep -iE "(bash -i|/dev/tcp|wget|curl|nc |netcat|chmod \+x)" 2>/dev/null || grep -iE "(execve.*bash -i|execve.*wget|execve.*curl|execve.*netcat)" "$audit_log" 2>/dev/null)
        if [ -n "$susp_execs" ]; then
            echo -e "${RED}Found suspicious command executions:${NC}"
            echo "$susp_execs" | tail -n 10
        else
            echo -e "${GREEN}No suspicious command executions found.${NC}"
        fi
        
        # Check for file permission changes to sensitive files
        echo -e "\n${WHITE}Permission changes to sensitive files:${NC}"
        perm_changes=$(ausearch -m CHMOD -m CHOWN -m ATTR 2>/dev/null | grep -iE "(/etc/passwd|/etc/shadow|/etc/sudoers|/etc/ssh|/var/log)" 2>/dev/null || grep -iE "(chmod|chown|attr).*(/etc/passwd|/etc/shadow|/etc/sudoers|/etc/ssh|/var/log)" "$audit_log" 2>/dev/null)
        if [ -n "$perm_changes" ]; then
            echo -e "${RED}Found permission changes to sensitive files:${NC}"
            echo "$perm_changes" | tail -n 10
        else
            echo -e "${GREEN}No suspicious permission changes found.${NC}"
        fi
    }
    
    # Run all log check functions
    check_auth_logs
    check_system_logs
    check_bash_history
    check_audit_logs
    
    echo -e "\n${CYAN}${BOLD}[+] Log analysis completed${NC}"
}
# Main function
main() {
    display_banner
    
    # Run security checks
    check_processes
    check_network
    check_system_files
    check_rootkits
    check_cron_jobs
    check_suid_sgid
    check_logs
    
    echo -e "\n${GREEN}${BOLD}[*] Security check completed.${NC}"
}

# Run the main function
main


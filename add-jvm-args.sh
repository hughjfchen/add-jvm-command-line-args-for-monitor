#!/usr/bin/env bash
set -Eeuo pipefail
#set -x

guard_bash_error () {
    set -Eeuo pipefail
}

# Log levels
INFO=0
WARN=1
ERROR=2
FATAL=3
DEBUG=4
DEFAULT_LOG_LEVEL=${ERROR}

my_exit () {
    echo "EXIT: - [HOST:$(hostname)]: - $(date +"%Y-%m-%d %H:%M:%S") - $1"
    exit "$2"
}

msg () {
    if [ $1 -le ${DEFAULT_LOG_LEVEL} ]; then
        echo "[HOST:$(hostname)]: - $(date +"%Y-%m-%d %H:%M:%S") - $2"
    fi
}

info () {
    msg ${INFO} "INFO: - $1"
}

warn () {
    msg ${WARN} "WARNING: - $1"
}

error () {
    msg ${ERROR} "ERROR: - $1"
}

fatal () {
    msg ${FATAL} "FATAL: - $1"
}

debug () {
    msg ${DEBUG} "DEBUG: - $1"
}

begin_banner () {
    info "$1 - $2 phase - begin"
}

done_banner () {
    info "$1 - $2 phase - done"
}

### turn path within script into absolute path
### must pass the calling string of the script as the first parameter
### e.g., ./path_to_script/script.sh
### or, /root/path_to_script/script.sh
### return the absolute path to the script with "echo" command
turn_to_absolute_path () {
    local SCRIPT_ABS_PATH_RAW="$(dirname "$1")"
    # turn SCRIPT_ABS_PATH into absolute path
    case ${SCRIPT_ABS_PATH_RAW} in
        /*) echo "${SCRIPT_ABS_PATH_RAW}" ;;
        \.\.*) echo "$PWD/${SCRIPT_ABS_PATH_RAW}" ;;
        \.*) echo "$PWD/${SCRIPT_ABS_PATH_RAW}" ;;
        *) echo "$PWD" ;;
    esac
}

### change CD to up to the project root directory
### must pass the absolute path to the script as the first parameter
change_CD_to_project_root () {
    cd "$1"
    local up_level=..
    local my_loop=10 # guard not to loop forever
    until ls "${up_level}"|grep -w DevOps > /dev/null 2>&1 && [ ${my_loop} -gt 0 ]
    do
        up_level=${up_level}/..
        my_loop=$(expr ${my_loop} - 1)
    done
    if [ ${my_loop} -eq 0 ]; then
        my_exit "Too many level up within the searching for DevOps directory,abort." 1
    fi
    cd "$1/${up_level}"
}

### check OS and distribution
### return the OS distribution and ID with "echo" command
check_dist_or_OS () {
    local MY_THE_DISTRIBUTION_ID=""
    local MY_THE_DISTRIBUTION_VERSION=""
    if [ -e /etc/os-release ]; then
        MY_THE_DISTRIBUTION_ID=$(grep -w "ID" /etc/os-release |awk -F"=" '{print $NF}'|sed 's/"//g')
	if [ "${MY_THE_DISTRIBUTION_ID}" == "ubuntu" ]; then
	    MY_THE_DISTRIBUTION_VERSION=$(grep -w "VERSION_ID" /etc/os-release |awk -F"=" '{print $NF}'|sed 's/"//g')
        else
            MY_THE_DISTRIBUTION_VERSION=$(grep -w "VERSION_ID" /etc/os-release |awk -F"=" '{print $NF}'|awk -F"." '{print $1}'|sed 's/"//g')
	fi
        echo "${MY_THE_DISTRIBUTION_ID} ${MY_THE_DISTRIBUTION_VERSION}"
    else if type uname > /dev/null 2>&1; then
             MY_THE_DISTRIBUTION_ID=$(uname -s)
             MY_THE_DISTRIBUTION_VERSION=$(uname -r)
             echo "${MY_THE_DISTRIBUTION_ID} ${MY_THE_DISTRIBUTION_VERSION}"
         else
             echo ""
         fi
    fi
}

### guard that the caller of the script must be root or has sudo right
guard_root_or_sudo () {
    if [[ $EUID > 0 ]] && ! sudo -v >/dev/null 2>&1; then
        return 1
    else
        return 0
    fi
}

### init script with check if root or sudo
init_with_root_or_sudo () {
    guard_bash_error

    if ! guard_root_or_sudo; then
        my_exit "You must be root or you must be sudoer to prepare the env for CI/CD." 1
    fi

    SCRIPT_ABS_PATH=$(turn_to_absolute_path $0)

    change_CD_to_project_root ${SCRIPT_ABS_PATH}

    THE_DISTRIBUTION_ID_VERSION=$(check_dist_or_OS)
    THE_DISTRIBUTION_ID=$(echo ${THE_DISTRIBUTION_ID_VERSION}|awk '{print $1}')
    THE_DISTRIBUTION_VERSION=$(echo ${THE_DISTRIBUTION_ID_VERSION}|awk '{print $2}')
}

### init script without check if root or sudo
init_without_root_or_sudo () {
    guard_bash_error

    SCRIPT_ABS_PATH=$(turn_to_absolute_path $0)

    change_CD_to_project_root ${SCRIPT_ABS_PATH}

    THE_DISTRIBUTION_ID_VERSION=$(check_dist_or_OS)
    THE_DISTRIBUTION_ID=$(echo ${THE_DISTRIBUTION_ID_VERSION}|awk '{print $1}')
    THE_DISTRIBUTION_VERSION=$(echo ${THE_DISTRIBUTION_ID_VERSION}|awk '{print $2}')
}

usage () {
    echo "$1 <WAS console URL> <console user name> <console user password> <result output file>"
    exit 1
}

check_dependencies () {
    begin_banner "top" "check_dependencies"
    type -P curl > /dev/null 2>&1 || my_exit "No curl found, please install it with your OS package manager." 1
    type -P elinks > /dev/null 2>&1 || my_exit "No elinks found, please install it with your OS package manager." 1
    done_banner "top" "check_dependencies"
}

gen_cookie_file_name () {
    if [ -d "/run/user/$(id -u)" ]; then
        mktemp -p "/run/user/$(id -u)" "my_c_$(date +%s).XXXXXX"
    elif [ -d "/dev/shm" ]; then
        mktemp -p "/dev/shm" "my_c_$(date +%s).XXXXXX"
    elif [ "X$TMPDIR" != "X" ]; then
        mktemp "$TMPDIR/my_c_$(date +%s).XXXXXX"
    fi
}

clean_up_cookie_file () {
    rm -fr "$1"
}

http_session_request () {
    local URL="$1"
    local COOKIE_FILE="$2"
    local POST_DATA="$3"
    if [ "X${POST_DATA}" == "X" ]; then
        # GET
        curl "${URL}" --location --insecure --cookie "${COOKIE_FILE}" --cookie-jar "${COOKIE_FILE}" --header "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9" --header "Accept-Language: en" 2>/dev/null | $4 $5
    else
        # POST
        curl "${URL}" --location --insecure --cookie "${COOKIE_FILE}" --cookie-jar "${COOKIE_FILE}" --header "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9" --header "Accept-Language: en" --header "Content-Type: application/x-www-form-urlencoded" --data "${POST_DATA}" 2>/dev/null | $4 $5
    fi
}

dump_page () {
   elinks -dump -dump-width $1 -no-numbering -no-references /dev/stdin
}

dump_page_with_ref () {
   elinks -dump -dump-width $1 /dev/stdin
}

first_req () {
    begin_banner "top - $1" "first_req"
    local MY_RESULT=$(http_session_request "$1" "$2" "" dump_page 80)
    if echo "${MY_RESULT}" | grep "User ID:" > /dev/null 2>&1 ; then
        if echo "${MY_RESULT}" | grep "Password:" > /dev/null 2>&1 ; then
            done_banner "top - $1" "first_req"
            return 0
        else
            warn "WAS not enable security yet, this is not recommended for a production system."
            done_banner "top - $1" "first_req"
        fi
    else
        my_exit "$1 - Failed to get login page, abort" 1
    fi
}

get_csrfid () {
    grep 'com.ibm.ws.console.CSRFToken' "$1" | awk '{print $NF}'
}

login () {
    begin_banner "top - $1" "login"
    local MY_URL_PREFIX=$(echo "$1" | awk -F":" '{print $1}')
    if [ "X${MY_URL_PREFIX}" == "Xhttps" ]; then
        local MY_RESULT=$(http_session_request "$1/j_security_check" "$2" "j_username=$3&j_password=$4&action=Log+in" dump_page 80)
    else
        local MY_RESULT=$(http_session_request "$1/login.do" "$2" "csrfid=HSLsc-EQMFOFAL1twm1_Rqz&username=$3&submit=Log+in" dump_page 80)
    fi

    if echo "${MY_RESULT}" | grep "You must use a browser that supports frames" > /dev/null 2>&1 ; then
        done_banner "top - $1" "login"
        return 0
    elif echo "${MY_RESULT}" | grep "Another user is currently logged in" > /dev/null 2>&1 ; then
        my_exit "$1 - Some one had logged in with the same user name, please check with admin console." 1
    elif echo "${MY_RESULT}" | grep "Recover" > /dev/null 2>&1 ; then
        my_exit "$1 - Some one had logged in with the same user name, did some changes, but not saved yet, please check admin console." 1
    fi
}

logout () {
    begin_banner "top - $1" "logout"
    http_session_request "$1/logout.do?csrfid=$3" "$2" "" dump_page 80 > /dev/null 2>&1
    done_banner "top - $1" "logout"
}

set_list_limit_to_1000 () {
    begin_banner "top - $1" "set_list_limit_to_1000"
    http_session_request "$1/preferenceAction.do?csrfid=$3&show=collapsed&text1=1000&dataType1=unsigned&node1=UI%2FCollections%2FApplicationServer%2FPreferences%23maximumRows&defaultValue1=20&node2=UI%2FCollections%2FApplicationServer%2FPreferences%23retainSearchCriteria&defaultValue2=false&list3=ALL&node3=UI%2FCollections%2FApplicationServer%2FPreferences%23roleFilter&defaultValue3=ALL&counter=3&submit2=Apply&submit2=Enter" "$2" "" dump_page 80 > /dev/null 2>&1
    done_banner "top - $1" "set_list_limit_to_1000"
}

extract_cell_and_server_list () {
    sed -n -e '/Cell\=/p' -e '1,/You can administer the following resources/d; /Total/q;p'
}

list_server () {
    http_session_request "$1/navigatorCmd.do?csrfid=$3&forwardName=ApplicationServer.content.main&WSC=true" "$2" "" dump_page 120 | extract_cell_and_server_list 0
}

extract_process_definition_from_detail_server () {
    if sed --version > /dev/null 2>&1 ; then
        sed -n --posix '/Use this page to configure a process definition/,/\<\/LI>/p' | grep "href" | awk '{print $2}' | awk -F"href=" '{print $NF}' | sed -n 's/^"\(.*\)"$/\1/p'
    else
        sed -n '/Use this page to configure a process definition/,/\<\/LI>/p' | grep "href" | awk '{print $2}' | awk -F"href=" '{print $NF}' | sed -n 's/^"\(.*\)"$/\1/p'
    fi
}

detail_server () {
    http_session_request "$1/applicationServerCollection.do?csrfid=$3&EditAction=true&contextId=cells%3A$4%3Anodes%3A$5%3Aservers%3A$6&resourceUri=server.xml&perspective=tab.configuration" "$2" "" extract_process_definition_from_detail_server 0
}

extract_jvm_from_process_definition () {
    if sed --version > /dev/null 2>&1 ; then
        sed -n --posix '/Use this page to configure advanced Java(TM) virtual machine settings/,/\<\/LI>/p' | grep "href" | awk '{print $2}' | awk -F"href=" '{print $NF}' | sed -n 's/^"\(.*\)"$/\1/p'
    else
        sed -n '/Use this page to configure advanced Java(TM) virtual machine settings/,/\<\/LI>/p' | grep "href" | awk '{print $2}' | awk -F"href=" '{print $NF}' | sed -n 's/^"\(.*\)"$/\1/p'
    fi
}

server_process_definition () {
    http_session_request "$1" "$2" "" extract_jvm_from_process_definition 0
}

extract_jvm_generic_command_line_args_from_jvm () {
    grep 'id="genericJvmArguments"' | sed -n 's/<.*>\(.*\)<.*>/\1/p'
}

server_jvm() {
    http_session_request "$1" "$2" "" extract_jvm_generic_command_line_args_from_jvm 0
}

server_jvm_generic_command_line_args() {
    http_session_request "$1" "$2" "$3" dump_page 80 > /dev/null 2>&1
}

save_change () {
    begin_banner "top - $1" "save_change"
    http_session_request "$1/syncworkspace.do?csrfid=$3&saveaction=save&directsave=true" "$2" "" dump_page 120 > /dev/null 2>&1
    done_banner "top - $1" "save_change"
}

filter_server_list () {
    local MY_ND_PAGE_CONTENT=$(echo "$1" | grep "[ ]")
    if [ "X${MY_ND_PAGE_CONTENT}" != "X" ] ; then
        echo "${MY_ND_PAGE_CONTENT}" | awk '{print $3 " " $4 " " $5}'
    else
        echo "$1"
    fi
}

get_real_base_url () {
    curl -i "$1" -L -k 2>/dev/null | egrep -A 10 '301 Moved Permanently|302 Found' | grep 'Location' | awk -F': ' '{print $2}' | tail -1 | sed 's/\/logon.jsp.*$//g' | sed 's/\/unsecureLogon.jsp.*$//g'
}

main () {
    local MY_COOKIE_FILE=$(gen_cookie_file_name)

    touch "$4"

    local MY_REAL_BASE_URL=$(get_real_base_url "$1")

    first_req "${MY_REAL_BASE_URL}" "${MY_COOKIE_FILE}"

    login "${MY_REAL_BASE_URL}" "${MY_COOKIE_FILE}" "$2" "$3"

    local MY_CSRFID=$(get_csrfid "${MY_COOKIE_FILE}")

    set_list_limit_to_1000 "${MY_REAL_BASE_URL}" "${MY_COOKIE_FILE}" "${MY_CSRFID}"

    begin_banner "top - $1" "list_server"
    local MY_CELL_AND_SERVER_LIST=$(list_server "${MY_REAL_BASE_URL}" "${MY_COOKIE_FILE}" "${MY_CSRFID}")
    done_banner "top - $1" "list_server"
    local MY_CELL=$(echo "${MY_CELL_AND_SERVER_LIST}" | sed -n 's/\(.*\)\(Cell=\)\(.*\)\(,\).*$/\3/p')
    local MY_SERVER_LIST_1=$(echo "${MY_CELL_AND_SERVER_LIST}" | sed '1d')
    local MY_SERVER_LIST=$(filter_server_list "${MY_SERVER_LIST_1}")

    declare -a MY_TO_BE_SET_SERVER=()

    local MY_INIT_PORT="0"

    info "Going through all servers to find the servers with port number set."
    while IFS= read -r MY_SERVER_ROW;
    do
        local MY_NODE=$(echo "${MY_SERVER_ROW}" | awk '{print $2}' | sed 's/ //')
        local MY_SERVER=$(echo "${MY_SERVER_ROW}" | awk '{print $1}' | sed 's/ //')
        local MY_HOST=$(echo "${MY_SERVER_ROW}" | awk '{print $3}' | sed 's/ //')

        begin_banner "${MY_HOST}-${MY_SERVER}" "detail_server"
        local MY_PROCESS_DEFINITION_LINK=$(detail_server "${MY_REAL_BASE_URL}" "${MY_COOKIE_FILE}" "${MY_CSRFID}" "${MY_CELL}" "${MY_NODE}" "${MY_SERVER}")
        done_banner "${MY_HOST}-${MY_SERVER}" "detail_server"

        begin_banner "${MY_HOST}-${MY_SERVER}" "server_process_definition"
        local MY_JVM_LINK=$(server_process_definition "${MY_REAL_BASE_URL}/${MY_PROCESS_DEFINITION_LINK}" "${MY_COOKIE_FILE}")
        done_banner "${MY_HOST}-${MY_SERVER}" "server_process_definition"

        begin_banner "${MY_HOST}-${MY_SERVER}" "server_jvm"
        local MY_JVM_GENERIC_COMMAND_LINE_ARGS_VALUE=$(server_jvm "${MY_REAL_BASE_URL}/${MY_JVM_LINK}" "${MY_COOKIE_FILE}")
        done_banner "${MY_HOST}-${MY_SERVER}" "server_jvm"

        local MY_ALREADY_SET_PORT=$(echo "${MY_JVM_GENERIC_COMMAND_LINE_ARGS_VALUE}" | awk -F"com.sun.management.jmxremote.port=" '{print $2}' | awk '{print $1}')

        if [ "X${MY_ALREADY_SET_PORT}" != "X" ]; then
            info "${MY_HOST}-${MY_SERVER} port number already set, will skip. The set port number will save in the output file."
            echo "${MY_HOST},${MY_CELL},${MY_NODE},${MY_SERVER},${MY_ALREADY_SET_PORT}" >> "$4"
            if [ "${MY_ALREADY_SET_PORT}" -ge "${MY_INIT_PORT}" ]; then
                MY_INIT_PORT="${MY_ALREADY_SET_PORT}"
            fi
        else
            MY_TO_BE_SET_SERVER+=("${MY_SERVER} ${MY_NODE} ${MY_HOST}")
        fi

    done <<< "${MY_SERVER_LIST}"

    info "Now actually set the to-be-set server's port number."

    if [ "X${MY_INIT_PORT}" == "X0" ]; then
        MY_INIT_PORT="8686"
    fi

    set +u
    for MY_I in "${!MY_TO_BE_SET_SERVER[@]}"; do
        local MY_NODE=$(echo "${MY_TO_BE_SET_SERVER}[$MY_I]" | awk '{print $2}' | sed 's/ //')
        local MY_SERVER=$(echo "${MY_TO_BE_SET_SERVER}[$MY_I]" | awk '{print $1}' | sed 's/ //')
        local MY_HOST=$(echo "${MY_TO_BE_SET_SERVER}[$MY_I]" | awk '{print $3}' | sed 's/ //')
        local MY_PORT=$((${MY_INIT_PORT}+${MY_I}+1))

        begin_banner "${MY_HOST}-${MY_SERVER}" "detail_server"
        local MY_PROCESS_DEFINITION_LINK=$(detail_server "${MY_REAL_BASE_URL}" "${MY_COOKIE_FILE}" "${MY_CSRFID}" "${MY_CELL}" "${MY_NODE}" "${MY_SERVER}")
        done_banner "${MY_HOST}-${MY_SERVER}" "detail_server"

        begin_banner "${MY_HOST}-${MY_SERVER}" "server_process_definition"
        local MY_JVM_LINK=$(server_process_definition "${MY_REAL_BASE_URL}/${MY_PROCESS_DEFINITION_LINK}" "${MY_COOKIE_FILE}")
        done_banner "${MY_HOST}-${MY_SERVER}" "server_process_definition"

        begin_banner "${MY_HOST}-${MY_SERVER}" "server_jvm"
        local MY_JVM_GENERIC_COMMAND_LINE_ARGS_VALUE=$(server_jvm "${MY_REAL_BASE_URL}/${MY_JVM_LINK}" "${MY_COOKIE_FILE}")
        done_banner "${MY_HOST}-${MY_SERVER}" "server_jvm"

        begin_banner "${MY_HOST}-${MY_SERVER}" "server_jvm_generic_command_line_args"
        server_jvm_generic_command_line_args "${MY_REAL_BASE_URL}/javaVirtualMachineDetail.do" "${MY_COOKIE_FILE}" "csrfid=${MY_CSRFID}&action=Edit&contextType=JavaVirtualMachine&genericJvmArguments=${MY_JVM_GENERIC_COMMAND_LINE_ARGS_VALUE}+-Djavax.management.builder.initial%3D+-Dcom.sun.management.jmxremote+-Dcom.sun.management.jmxremote.port%3D${MY_PORT}+-Dcom.sun.management.jmxremote.ssl%3Dfalse+-Dcom.sun.management.jmxremote.authenticate%3Dfalse&save=OK"
        done_banner "${MY_HOST}-${MY_SERVER}" "server_jvm_generic_command_line_args"

        echo "${MY_HOST},${MY_CELL},${MY_NODE},${MY_SERVER},${MY_PORT}" >> "$4"
    done
    set -u

    save_change "${MY_REAL_BASE_URL}" "${MY_COOKIE_FILE}" "${MY_CSRFID}"

    logout "${MY_REAL_BASE_URL}" "${MY_COOKIE_FILE}" "${MY_CSRFID}"

    clean_up_cookie_file "${MY_COOKIE_FILE}"
}

[ $# != 4 ] && usage "$0"

check_dependencies

main "$1" "$2" "$3" "$4"

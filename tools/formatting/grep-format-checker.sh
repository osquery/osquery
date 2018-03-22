#! /bin/bash

function red() {
	echo -e "\033[1;31m$1\033[0m"
}

function green() {
	echo -e "\033[1;32m$1\033[0m"
}

STDSTRING_EQ=$(egrep -rn "(const)* std::string [a-zA-Z]+ = \".*\";" $SOURCE_DIR/osquery)

if [[ $STDSTRING_EQ != "" ]]; then
	red "[-] Usage of std::string var = \"...\" detected. Please use braces"
	red "[-] Detected usages:"
	echo "$STDSTRING_EQ"
else
	green "[+] No instances of std::string var = \"...\" found"
fi

STDSTRING_PAREN=$(egrep -rn "(const)* std::string\ [a-zA-Z]+\(\".*\"\)" $SOURCE_DIR/osquery)

if [[ $STDSTRING_PAREN != "" ]]; then
	red "[-] Usage of std::string var(\"...\") detected. Please use braces"
	red "[-] Detected usages:"
	echo "$STDSTRING_PAREN"
else
	green "[+] No instances of std::string var(\"...\") found"
fi

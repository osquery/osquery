#! /bin/bash

CODEMOD=$(which codemod)
CODEMOD_FLAGS="-d $SOURCE_DIR --accept-all --extensions cpp,mm"

function red() {
	echo -e "\033[1;31m$1\033[0m"
}

function green() {
	echo -e "\033[1;32m$1\033[0m"
}

function applyFixes() {
	if [[ $CODEMOD != "" ]]; then
		green "[+] Applying fixes"
		eval $CODEMOD $CODEMOD_FLAGS $2 2>&1 > /dev/null
		if [[ $? == 0 ]]; then
			green "[+] Fixes successfully applied"
			return
		fi
		red "[-] Fixes could not be applied"
	fi
	red "[-] Detected usages:"
	echo "$STDSTRING_EQ"
}

STDSTRING_EQ=$(egrep -rn "(const)* std::string [a-zA-Z]+ = \".*\";" $SOURCE_DIR)
STDSTRING_EQ_CM="'(.*)std::string ([a-zA-Z]+) = \"(.*)\";' '\1std::string \2 {\"\3\"};'"

if [[ $STDSTRING_EQ != "" ]]; then
	red "[-] Usage of std::string var = \"...\" detected. Please use braces"
	applyFixes "$STDSTRING_EQ" "$STDSTRING_EQ_CM"
else
	green "[+] No instances of std::string var = \"...\" found"
fi

STDSTRING_PAREN=$(egrep -rn "(const)* std::string\ [a-zA-Z]+\(\".*\"\)" $SOURCE_DIR)
STDSTRING_PAREN_CM="'(.*)std::string ([a-zA-Z]+)\(\"(.*)\"\);' '\1std::string \2 {\"\3\"};'"

if [[ $STDSTRING_PAREN != "" ]]; then
	red "[-] Usage of std::string var(\"...\") detected. Please use braces"
	applyFixes "$STDSTRING_PAREN" "$STDSTRING_PAREN_CM"
else
	green "[+] No instances of std::string var(\"...\") found"
fi

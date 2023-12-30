#!/bin/bash

exit_with_message() {
	echo "${1}"
	exit 1
}

if [[ $# -lt 1 || $# -gt 5 ]]; then
	exit_with_message "usage: ${0} <ghidra_home> [libs_dir] [projects_dir] [logs_dir] [output_dir]"
fi

ghidra_home="${1}"
ghidra_headless="${ghidra_home}/support/analyzeHeadless"
ghidra_scripts="${ghidra_home}/Ghidra/Features/FunctionID/ghidra_scripts"
libs_dir="${2:-libs}"
projects_dir="${3:-projects}"
logs_dir="${4:-logs}"
output_dir="${5:-fid_files}"

if [[ ! -d "${ghidra_home}" ]]; then
	exit_with_message "Ghidra home directory \"${ghidra_home}\" doesn't exist"
fi

if [[ ! -x "${ghidra_headless}" ]]; then
	exit_with_message "Can't find 'analyzeHeadless' or it's not executable: ${ghidra_headless}"
fi

if [[ ! -d "${ghidra_scripts}" ]]; then
	exit_with_message "FunctionID scripts directory doesn't exist: ${ghidra_scripts}"
fi

mkdir -p "${projects_dir}" "${logs_dir}" "${output_dir}"

while IFS="" read -r lib_variant || [[ -n "${lib_variant}" ]]; do
	project=$(echo "${lib_variant}" | cut -d/ -f1)
	project_dir="${projects_dir}/${project}"

	echo "Processing lib variant: ${project}" 

	mkdir -p "${project_dir}"

	rm -f "${logs_dir}/${project}"*.log

	# Init the project, import all the binaries from the needed library and analyze them
	printf "\tImporting and analyzing files\n"
	"${ghidra_headless}" "${project_dir}" "${project}" \
		-import "${libs_dir}/${project}" \
		-recursive \
		-scriptPath "$ghidra_scripts" \
		-preScript FunctionIDHeadlessPrescript.java \
		-postScript FunctionIDHeadlessPostscript.java \
		-scriptlog "${logs_dir}/${project}-scripts.log" \
		-log "${logs_dir}/${project}-analyze.log" \
		-max-cpu "$(nproc)" > /dev/null 2>&1

	# FunctionIDHeadlessPostscript writes errors when doing its work, which are not
	# critical for subsequent logic, so we ignore them
	if grep -q ERROR "${logs_dir}/${project}-analyze.log" | grep -v FunctionIDHeadlessPostscript; then 
		exit_with_message "FAILED! Please check logs: ${logs_dir}/${project}-analyze.log"
	fi

	# Find all unique langids in the analyzer output
	langids=$(sed -nr 's/^.*Using Language\/Compiler: (.+)$/\1/p' "${logs_dir}/${project}-analyze.log" | sed 's/:[^:]*$//' | sort -u)

	while read -r langid; do
		printf "\tGenerating FidDB file\n"

		read -r pname variant name version arch < <(echo "${lib_variant}" | tr '/' ' ')

		# Generate a .properties file for each library
		export logs_dir project_dir project langid variant
		envsubst < fidb_generation.template > "${project_dir}/CreateMultipleLibraries.properties"

		# All of these files must exist before running the CreateMultipleLibraries script
		cat /dev/null > "${logs_dir}/${project}-duplicates.txt"
		cat /dev/null > "${project_dir}/common_symbols.txt"

		# Create an empty fidb file and fill it with the data afterwards
		"${ghidra_headless}" "${project_dir}" "${project}" \
		-noanalysis \
		-propertiesPath "${project_dir}" \
		-scriptPath "${ghidra_scripts};$(pwd)/ghidra_scripts" \
		-preScript CreateEmptyFidDatabase.java "${output_dir}/${project}.fidb" \
		-preScript CreateMultipleLibraries.java \
		-log "${logs_dir}/${project}-generation.log" > /dev/null 2>&1

		if ! grep -q ERROR "${logs_dir}/${project}-generation.log"; then 
			echo -e "\tOptimizing FidDB file"

			# Pack the database
			"${ghidra_headless}" "${project_dir}" "${project}" \
			-noanalysis \
			-scriptPath "ghidra_scripts" \
			-preScript RepackFidHeadless.java "${output_dir}/${project}.fidb" \
			-log "${logs_dir}/${project}-generation.log" > /dev/null 2>&1
		fi

		if grep -q ERROR "${logs_dir}/${project}-generation.log"; then 
			rm -f "${output_dir}/${project}.fidb"*
			exit_with_message "FAILED! Please check logs: ${logs_dir}/${project}-generation.log"
		fi
	done <<< "${langids}"

	echo "DONE!"
done < "${libs_dir}/all_libs"


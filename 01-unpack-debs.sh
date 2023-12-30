#!/bin/bash

set -e

exit_with_message() {
	echo "${1}"
	exit 1
}

unpack_deb() {
	tmp_dir=$(mktemp -d)
	if [ ! -e "${tmp_dir}" ]; then
		exit_with_message "Failed to create temp directory"
	fi
	trap 'rm -rf -- "${tmp_dir}"' EXIT

	pushd "${tmp_dir}" 1> /dev/null

	# first unpack data.tar.gz from deb and copy all static libraries back to the
	# libs directory
	ar x "${debfile}"
	tar -xf data.tar.*
	find "$(pwd)" -type f \( -iname "*.a" -o -iname '*.lib' \)  -exec mv {} "${1}/." \;

	popd 1> /dev/null
	rm -rf -- "${tmp_dir}"
}

unpack_libs() {
	# for each lib, create a subdir which is equal to the lib name and extract all *.o there
	find "${1}" -type f \( -iname '*.a' -o -iname '*.lib' \) | while read -r lib; do
		subdir=$(echo "${lib}" | sed 's/\.[^.]*$//')

		mkdir -p "${subdir}"
		ar x "${lib}" --output "${subdir}"
	done

	# remove everything which is not object files, including symlinks
	find "${1}" -type f \( -not -iname '*.o' -and -not -iname '*.obj' \) -exec rm {} \;
	find "${1}" -type l -exec rm {} \;
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
	exit_with_message "usage: ${0} <path> <variant> [output_dir]"
fi

path="${1}"
variant="${2}"
output_dir="${3:-libs}"

if [[ -z "${variant}" ]]; then
	exit_with_message "deb 'variant' should be set"
fi

if [[ ! -d "${path}" ]]; then
	exit_with_message "path \"${path}\" doesn't exist"
fi

mkdir -p "${output_dir}"

find "${path}" -type f -iname "*.deb" | while read -r file; do
	debfile=$(readlink -f "${file}")
	pkg=$(basename "${debfile}" .deb)

	# only Debian package naming scheme is supported
	# https://www.debian.org/doc/manuals/debian-faq/pkg-basics.en.html#pkgname
	read -r name version arch < <(echo "${pkg}" | tr '_' ' ')

	# this path scheme is required for the ghidra's 'CreateMultipleLibraries' script
	# otherwise the fidb metadata will be incorrect
	lib_variant_path="${variant}/${name}/${version}/${arch}"
	lib_variant_name=$(echo "${lib_variant_path}" | tr '/' '_')
	path="${output_dir}/${lib_variant_name}/${lib_variant_path}"

	mkdir -p "${path}"
	path=$(readlink -f "${path}")

	unpack_deb "${path}"
	unpack_libs "${path}"

	echo "${lib_variant_name}/${lib_variant_path}" >> "${output_dir}/all_libs"
done


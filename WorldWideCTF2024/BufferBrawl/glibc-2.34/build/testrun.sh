#!/bin/bash
builddir=`dirname "$0"`
GCONV_PATH="${builddir}/iconvdata"

usage () {
cat << EOF
Usage: $0 [OPTIONS] <program> [ARGUMENTS...]

  --tool=TOOL  Run with the specified TOOL. It can be strace, valgrind or
               container. The container will run within support/test-container.
EOF

  exit 1
}

toolname=default
while test $# -gt 0 ; do
  case "$1" in
    --tool=*)
      toolname="${1:7}"
      shift
      ;;
    --*)
      usage
      ;;
    *)
      break
      ;;
  esac
done

if test $# -eq 0 ; then
  usage
fi

case "$toolname" in
  default)
    exec   env GCONV_PATH="${builddir}"/iconvdata LOCPATH="${builddir}"/localedata LC_ALL=C  "${builddir}"/elf/ld-linux-x86-64.so.2 --library-path "${builddir}":"${builddir}"/math:"${builddir}"/elf:"${builddir}"/dlfcn:"${builddir}"/nss:"${builddir}"/nis:"${builddir}"/rt:"${builddir}"/resolv:"${builddir}"/mathvec:"${builddir}"/support:"${builddir}"/crypt:"${builddir}"/nptl ${1+"$@"}
    ;;
  strace)
    exec strace  -EGCONV_PATH=/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/iconvdata  -ELOCPATH=/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/localedata  -ELC_ALL=C  /home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/elf/ld-linux-x86-64.so.2 --library-path /home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/math:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/elf:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/dlfcn:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/nss:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/nis:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/rt:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/resolv:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/mathvec:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/support:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/crypt:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/nptl ${1+"$@"}
    ;;
  valgrind)
    exec env GCONV_PATH=/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/iconvdata LOCPATH=/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/localedata LC_ALL=C valgrind  /home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/elf/ld-linux-x86-64.so.2 --library-path /home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/math:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/elf:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/dlfcn:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/nss:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/nis:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/rt:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/resolv:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/mathvec:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/support:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/crypt:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/nptl ${1+"$@"}
    ;;
  container)
    exec env GCONV_PATH=/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/iconvdata LOCPATH=/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/localedata LC_ALL=C  /home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/elf/ld-linux-x86-64.so.2 --library-path /home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/math:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/elf:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/dlfcn:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/nss:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/nis:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/rt:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/resolv:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/mathvec:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/support:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/crypt:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/nptl /home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/support/test-container env GCONV_PATH=/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/iconvdata LOCPATH=/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/localedata LC_ALL=C  /home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/elf/ld-linux-x86-64.so.2 --library-path /home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/math:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/elf:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/dlfcn:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/nss:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/nis:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/rt:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/resolv:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/mathvec:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/support:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/crypt:/home/cl1nical/Desktop/pwnlibrary/WorldWideCTF2024/BufferBrawl/glibc-2.34/build/nptl ${1+"$@"}
    ;;
  *)
    usage
    ;;
esac

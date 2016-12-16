#!/bin/bash
# $Id$

MYNAME=${0##*/}
XSLTPROC="$(which xsltproc)"
RM="$(which rm)"
CHMOD="$(which chmod)"
TOUCH="$(which touch)"
DIRNAME="$(which dirname)"

usage() {
    echo "Usage: ${MYNAME} [options]"
    echo "    -f - path to source directory with xml files"
    echo "    -t - path to destination file for html report"
    echo "    -u - path to concatenating xsl file"
    echo "    -s - path to xsl stylesheet"
    echo "    -d - debug mode"
    exit 1
}

SOURCE_DIR=""
DESTINATION_DIR=""
XSLCONCAT=""
XSLSTYLE=""
DEBUG=0
J=0
ARG=( "${@}" )
for i in ${@}; do
    J=$((${J}+1))
    case $i in
        "-f") SOURCE_DIR=${ARG[${J}]} ;;
        "-t") DESTINATION_PATH=${ARG[${J}]} ;;
        "-u") XSLCONCAT=${ARG[${J}]} ;;
        "-s") XSLSTYLE=${ARG[${J}]} ;;
        "-d") DEBUG=1 ;;
        esac
    done

[ ${DEBUG} -eq 1 ] && set -x
[ "x${SOURCE_DIR}" = "x" ] && echo "Source directory must be specified." && usage
[ "x${DESTINATION_PATH}" = "x" ] && echo "Destination directory must be specefied." && usage
[ "x${XSLCONCAT}" = "x" ] && echo "XSL concatenation file must be specefied." && usage
[ "x${XSLSTYLE}" = "x" ] && echo "XSL stylesheet must be specefied." && usage
[ ! -d ${SOURCE_DIR} ] && echo "Cannot open source directory." && usage
[ ! -d "$(${DIRNAME} ${DESTINATION_PATH})" ] && echo "Cannot open destination directory." && usage
[ ! -f ${XSLCONCAT} ] && echo "Cannot open XSL concatenation file." &&  usage
[ ! -f ${XSLSTYLE} ] && echo "Cannot open XSL stylesheet." && usage


# Make absolute path from relative one
if [ "${SOURCE_DIR:0:1}" = "/" ]; then
    SDIR=${SOURCE_DIR}
else
    SDIR=${PWD}/${SOURCE_DIR}
    fi
if [ "${DESTINATION_PATH:0:1}" = "/" ]; then
    DPATH=${DESTINATION_PATH}
else
    DPATH=${PWD}/${DESTINATION_PATH}
    fi
TMP=/tmp

# Verify that script has access to create output file
if [ -d ${DPATH} ]; then
    echo "${DPATH} is a directory."
    exit 1
    fi
${TOUCH} ${DPATH}
if [ ! $? -eq 0 ]; then
    echo "Error in access to ${DPATH}."
    exit 1
    fi

# Create index.xml
HEADER='<?xml version="1.0" encoding="utf-8"?><files>'
FOOTER='</files>'
IXML=${TMP}/${MYNAME}-`date +%s`-index.xml
echo ${HEADER} > ${IXML}
for xmlfile in ${SDIR}/*.xml; do
    echo "<file name=\"${xmlfile}\" />" >> ${IXML}
    done
echo ${FOOTER} >> ${IXML}

# Create united xml report
TMPXML=${TMP}/${MYNAME}-`date +%s`-tmp.xml
${XSLTPROC} ${XSLCONCAT} ${IXML} > ${TMPXML}
${RM} ${IXML}

# Create html report
#HTML_NAME=`date +%Y-%m-%d_%H:%M`.html
${XSLTPROC} ${XSLSTYLE} ${TMPXML} > ${DPATH}
${RM} ${TMPXML}

# Add read permissions to file
${CHMOD} 644 ${DPATH}


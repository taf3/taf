#!/usr/bin/env python
"""
@copyright Copyright (c) 2011 - 2016, Intel Corporation.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

@file  generate_documentation.py

@summary  This script generates TAF Doxygen documentation(HTML and RTF files)
"""

import os
import sys
import logging
import argparse
import subprocess


def create_argparser():
    arg_parser = argparse.ArgumentParser(
        description="Generate TAF Doxygen documentation")
    arg_parser.add_argument(
        '--html',
        help='Generate HTML documentation',
        action="store_true"
    )
    arg_parser.add_argument(
        '--rtf',
        help='Generate RTF documentation',
        action="store_true"
    )
    arg_parser.add_argument(
        '--internal',
        help='Generate version for internal use',
        action="store_true"
    )
    arg_parser.add_argument(
        '--version',
        default="$(git describe --abbrev=0)",
        help='Setting version of project in documentation (e.g, --version 1.2)'
             'The most recent tag from GIT by default'
    )
    arg_parser.add_argument(
        '--config_path',
        help='Path to Doxygen configuration file',
        default="../docs"
    )
    arg_parser.add_argument(
        '--output_dir',
        help='Path to output directory',
        default="../docs"
    )
    arg_parser.add_argument(
        '--source_files',
        help='Path to source files (e.g, --source_files ~/taf)',
        default="../"
    )

    return arg_parser


def generate_documentation(option, doc_type):
    """
    @brief  Generate Doxygen documentation
    @param option:  Command line arguments
    @type  option:  argparse.ArgumentParser
    @param doc_type:  Type of documentation: "html" or "rtf"
    @type  doc_type:  str
    @return:  None
    """
    # Define path to Doxygen configuration file
    docs_path = os.path.normpath(os.path.expanduser(option.config_path))
    config = os.path.join(docs_path, "Doxyfile.in")
    # Define build settings
    settings = []
    settings.append("cat {0}".format(config))
    settings.append("echo 'OUTPUT_DIRECTORY={0}'".format(option.output_dir))
    settings.append("echo 'IMAGE_PATH={0}'".format(os.path.join(docs_path, "images")))
    settings.append("echo PROJECT_NUMBER={0}".format(option.version))
    settings.append("echo 'INPUT={0}'".format(option.source_files))

    # Verify that config file exists
    if os.path.isfile(config):
        # Define settings for HTML documentation
        if doc_type == "html":
            settings.append("echo 'GENERATE_HTML=YES'")
            settings.append("echo 'GENERATE_RTF=NO'")
            if option.internal:
                layout_file = "../docs/DoxygenLayoutInternal.xml"
                settings.append("echo 'LAYOUT_FILE={0}'".format(layout_file))
            else:
                layout_file = "../docs/DoxygenLayout.xml"
                settings.append("echo 'LAYOUT_FILE={0}'".format(layout_file))
            command = "({0})".format("; ".join(settings))
        # Define settings for RTF documentation
        else:
            settings.append("echo 'GENERATE_HTML=NO'")
            settings.append("echo 'GENERATE_RTF=YES'")
            settings.append("echo 'RTF_HYPERLINKS=YES'")
            if option.internal:
                patterns = "._* */.git/* */tests/* */unittests/* __init__.py " \
                           "*/2_6_overview_directory_structure.dox " \
                           "*/3_2_taf_install_environment.dox"
                settings.append("echo 'EXCLUDE_PATTERNS={0}'".format(patterns))
            else:
                patterns = "._* */.git/* */tests/* */unittests/* " \
                           "__init__.py *internal.dox *gerrit.dox *git.dox *teamforge.dox"
                settings.append("echo 'EXCLUDE_PATTERNS={0}'".format(patterns))
            command = "({0})".format("; ".join(settings))

        # Setup and generate Doxygen documentation
        logging.info("Generating %s documentation", doc_type.upper())
        process = subprocess.Popen(command + " | doxygen -", shell=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p_out, p_err = process.communicate()
        retcode = process.wait()
        if retcode != 0:
            logging.error("Failed to generate %s documentation", doc_type.upper())
            sys.exit(1)
        path_to_docs = "/".join([os.path.abspath(option.output_dir), doc_type])
        logging.info("Documentation is located in: %s", path_to_docs)

    else:
        logging.error("Doxygen configuration file doesn't exist in: %s", docs_path)
        sys.exit(1)

if __name__ == '__main__':
    # Parse command line options
    _arg_parser = create_argparser()
    _args = _arg_parser.parse_args()
    # Configure logging system
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
    docs_type = {}
    # Define documentation types to generate
    if _args.html:
        docs_type["html"] = _args.html
    if _args.rtf:
        docs_type["rtf"] = _args.rtf
    if not docs_type:
        logging.error("Documentation type isn't specified")
        logging.info("Use [-h] or [--help] to show description of arguments")
        sys.exit(1)
    # Generate documentations
    for doc in docs_type:
        generate_documentation(_args, doc)

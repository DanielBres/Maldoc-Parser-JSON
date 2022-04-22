"""
Automate testing of multiple samples.
=====================================
Change the REPORTS_OUT_DIR and REPORTS_OUT_DIR.
Use "my_os" variable to determine the OS type in order for the code to run both on Windows and on Linux systems.

"""

import os
import glob
import subprocess


def list_archive_files(path=[REPORTS_OUT_DIR]", my_os="Windows"):
    files = None

    if my_os == "Windows":
        files = glob.glob(path + "\\*.*")
    if my_os == "Linux":
        files = glob.glob(path + "/*.*")
    samples = list(dict.fromkeys(files))

    return samples


def main():
    samples = list_archive_files()
    reports_path="[REPORTS_OUT_DIR]"

    for sample in samples:
        head, tail = os.path.split(sample)
        outfile = "%s\\%s.json" % (reports_path, tail)
        with open(outfile, "w") as out:
            batch = "python maldoc_parser_unified.py \"%s\"" % sample
            subprocess.call(batch, stdout=out)
        out.close()


if __name__ == "__main__":
    main()

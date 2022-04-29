"""
Automate testing of multiple samples.
=====================================
Change the REPORTS_OUT_DIR and REPORTS_OUT_DIR.
Use "my_os" variable to determine the OS type in order for the code to run both on Windows and on Linux systems.

"""

import os
import glob
import subprocess


def list_archive_files(path="/home/remnux/Maldoc-Parser-JSON/samples", my_os="Linux"):
    files = None
    
    if my_os == "Windows":
        files = glob.glob(path + "\\*.*")
    
    if my_os == "Linux":
        files = glob.glob(path + "/*.*")
    samples = list(dict.fromkeys(files))
    return my_os, samples


def main():
    my_os, samples = list_archive_files()
    reports_path = "./reports"

    for sample in samples:
        head, tail = os.path.split(sample)
        outfile = "%s/%s.json" % (reports_path, tail)
        
        with open(outfile, "w") as out:
            
            if my_os == "Windows":
                batch = "python maldoc_parser.py \"%s\"" % sample
                subprocess.call(batch, stdout=out)
            
            if my_os == "Linux":
                #argv1 = "maldoc_parser_unified.py"
                #argv2 = "\"%s\"" % sample
                #subprocess.run(["python", argv1, argv2], stdout=out)
                batch = "/usr/bin/python3.8"
                script = "maldoc_parser.py"
                maldoc = "%s" % sample
                subprocess.run([batch, script, maldoc], stdout=out)
        
        out.close()


if __name__ == "__main__":
    main()

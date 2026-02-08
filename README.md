# Info
Dedup is a cross-platform command-line Python application that is designed to efficiently detect and report duplicate files on your system.

## Requirements
* Linux (fully tested), Windows, MacOS
* Python > 3.6
* 3rd party module free ✅

## Installation
`git clone https://github.com/brightio/dedup`\
or\
`wget https://raw.githubusercontent.com/brightio/dedup/main/dedup.py`

## Modes
### ➤ Normal mode
It detects duplicate files in the given directories and/or files.
![normal](https://github.com/user-attachments/assets/42b8dd6a-9617-4464-b37b-e258a60125ca)

### ➤ Target mode
It detects if the given directories and/or files exist in the target directories and/or files which can be specified with -t.
![target](https://github.com/user-attachments/assets/38528d36-505b-458f-8654-610f113afcbe)

## File treatment
* Empty files are excluded.
* Symbolic links are not followed.
* Hard links are considered to be the same file.
* Hidden files and directories are excluded (they can be included with -a, -hf, -hd)
* The duplicate sets are sorted by the space that will be freed if the duplicate files are removed (use -s to sort by individual file size)
* The hashing algorithm to detect duplicate files is the SHA1. Further verification by typing 'v' in the interactive menu which will verify the results using MD5.
## Item filtering
* Use -min and -max for minimum and maximum file size respectively. The size can be specified like 500K, 2M, 10G etc.
* Use -xf and -xd to exclude files and directories respectively. The value will be treated as a regular expression.
Note: More elaborate filtering can be achieved via external programs such as 'find', as 'dedup' accepts newline separated item list from stdin.

## Command line options
```
usage: dedup.py [-h] [-t TARGETS] [-s] [-u] [-S] [-I] [-V] [-xf EXCLUDE_FILES] [-xd EXCLUDE_DIRECTORIES] [-min MIN_SIZE] [-max MAX_SIZE] [-a] [-hf] [-hd] [-v]
                [ITEMS ...]

This program detects duplicate files.

positional arguments:
  ITEMS                 Files/Directories to detect duplicates

options:
  -h, --help            show this help message and exit
  -t TARGETS, --targets TARGETS
                        Files/Directories that we want to check if the ITEMS exist in there
  -s, --sort-size       Sort duplicates by size (Default: Saving size)
  -u, --show-unique     Show also unique files (Default: No)
  -S, --only-stats      Show only statistics
  -I, --non-interactive
                        Disable interactive prompts (Default: Enabled)
  -V, --verbose         Show files while they are being read
  -xf EXCLUDE_FILES, --exclude-files EXCLUDE_FILES
                        Files to exclude (regex)
  -xd EXCLUDE_DIRECTORIES, --exclude-directories EXCLUDE_DIRECTORIES
                        Directories to exclude (regex)
  -min MIN_SIZE, --min-size MIN_SIZE
                        Ommit files smaller than SIZE (Bytes).
  -max MAX_SIZE, --max-size MAX_SIZE
                        Ommit files larger than SIZE (Bytes).
  -a, --include-hidden  Include hidden files and directories (Default: No)
  -hf, --include-hidden-files
                        Include hidden files (Default: No)
  -hd, --include-hidden-directories
                        Include hidden directories (Default: No)
  -v, --version         Show version
```

## TODO
* Improve duplicate detection performance and interactive menu navigation.
* Ability to save session, TAB delimited output and a file with the files to be deleted.
* Ability to look into archive/zipped files.
* Detect duplicate directories.
* Stop hashing candidate duplicate files if at some point their data are different. This will save time with large files (like disk images) where their sizes are the same but their data differ.

## Known Issues
* Ctrl-C for stopping the program while searching for duplicates doesn't work on Windows yet.
* Exiting the program on MacOS produce a warning like: `/Library/Frameworks/Python.framework/Versions/3.11/lib/python3.11/multiprocessing/resource_tracker.py:224: UserWarning: resource_tracker: There appear to be 9 leaked semaphore objects to clean up at shutdown` which I can't solve yet.

## Contribution
If you want to contribute to this project please report bugs, unexpected program behaviours and/or new ideas.

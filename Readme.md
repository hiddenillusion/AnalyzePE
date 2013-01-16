AnalyzePE.py
=============

Wraps around various tools and provides some additional checks/information to produce a centralized report of a PE file.

Requirements
------------
	* Adobe Malware Classifier
	* Hachoir-subfile
	* pescanner (modified version included on my github)
	* pefile (newer version), peutils
	* verify sigs' fingerprint.py
	* python-magic
	* pyasn1
	* m2crypto
	* pydasm
	* yara
	
Optional
--------
	* clamav

Usage
-----
	usage: AnalyzePE.py [-h] [-m MOVE] [-v] Path

	Wraps around various tools to produce a centralized report of a PE file.

	positional arguments:
	Path                  Path to directory/file(s) to be scanned

	optional arguments:
	-h, --help            show this help message and exit
	-m MOVE, --move MOVE  Directory to move files triggering YARA hits to
	-v, --verbose         Add additional information to analysis output

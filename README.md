# fuxploider

[![Python 3.5|3.6](https://img.shields.io/badge/python-3.5%2F3.6-green.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/almandin/fuxploider/master/LICENSE.md)

fuxploider is an open source penetration testing tool that automates the process of detecting and exploiting file upload forms flaws. This tool is able to detect the file types allowed to be uploaded and is able to detect which technique will work best tu upload web shells or any malicious file on the desired web server.


### Use

python3 fuxploider.py URL errReg [--data]

python3 fuxploider.py http://loremipsum.com/form/uploadFiles.php "wrong file type"

URL : base URL where a file upload form is present, to be tested

errReg : regular expression matching a failed upload (bad extension or similar) to detect fails and succeeds

--data : additionnal post data to be sent with the form

[!] legal disclaimer : Usage of fuxploider for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

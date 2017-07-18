# fuxploider
File upload technique suggester tool for penetration testing web applications.

In a penetration test, exploiting a file upload form can be quite tedious as there are several techniques where you have to test for many
combinations of different file extensions, with or without null byte, with the right or the bad mime type.

This software tries to help automating stuff, generating every combination of extensions, null bytes and mime types.

### Use

python3 fuxploider.py URL errReg [--data]

python3 fuxploider.py http://loremipsum.com/form/uploadFiles.php "wrong file type"

URL : base URL where a file upload form is present, to be tested

errReg : regular expression matching a failed upload (bad extension or similar) to detect fails and succeeds

--data : additionnal post data to be sent with the form

For educational purpose only, the mainteners of this project can't be responsible for any of your activities using this piece of software.
No warranty that it just works.

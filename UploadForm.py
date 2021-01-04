import re
import os
import logging
import sys
import tempfile
import concurrent.futures
from threading import Lock
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from utils import *


class UploadForm:
    def __init__(self, notRegex, trueRegex, session, size, postData,
                 uploadsFolder=None, formUrl=None, formAction=None, inputName=None):
        self.logger = logging.getLogger("fuxploider")
        self.postData = postData
        self.formUrl = formUrl
        url = urlparse(self.formUrl)
        self.schema = url.scheme
        self.host = url.netloc
        self.uploadUrl = urljoin(formUrl, formAction)
        self.session = session
        self.trueRegex = trueRegex
        self.notRegex = notRegex
        self.inputName = inputName
        self.uploadsFolder = uploadsFolder
        self.size = size
        self.validExtensions = []
        self.httpRequests = 0
        self.codeExecUrlPattern = None  # Pattern for code exec detection using true regex findings
        self.logLock = Lock()
        self.stopThreads = False
        self.shouldLog = True

    # Searches for a valid html form containing an input file, sets object parameters correctly
    def setup(self, initUrl):
        self.formUrl = initUrl
        url = urlparse(self.formUrl)
        self.schema = url.scheme
        self.host = url.netloc

        self.httpRequests = 0
        try:
            initGet = self.session.get(self.formUrl, headers={"Accept-Encoding":None})
            self.httpRequests += 1
            if self.logger.verbosity > 1:
                printSimpleResponseObject(initGet)
            if self.logger.verbosity > 2:
                print(f"\033[36m{initGet.text}\033[m")
            if initGet.status_code < 200 or initGet.status_code > 300:
                self.logger.critical("Server responded with following status: %s - %s",
                                     initGet.status_code, initGet.reason)
                sys.exit(1)
        except Exception as e:
                self.logger.critical("%s: Host unreachable (%s)", getHost(initUrl), e)
                sys.exit(1)

        # Detect and get the form's data
        detectedForms = self.detectForms(initGet.text)
        if not detectedForms:
            self.logger.critical("No HTML forms found.")
            sys.exit()
        if len(detectedForms) > 1:
            self.logger.critical("%s forms found containing file upload inputs, no way to choose which one to test.", len(detectedForms))
            sys.exit()
        if len(detectedForms[0][1]) > 1:
            self.logger.critical("%s file inputs found inside the same form, no way to choose which one to test.", len(detectedForms[0]))
            sys.exit()

        self.inputName = detectedForms[0][1][0]["name"]
        self.logger.debug("Found the following file upload input: %s", self.inputName)
        formDestination = detectedForms[0][0]

        try:
            self.action = formDestination["action"]
        except:
            self.action = ""
        self.uploadUrl = urljoin(self.formUrl, self.action)

        self.logger.debug("Using following URL for file upload: %s", self.uploadUrl)

        if not self.uploadsFolder and not self.trueRegex:
            self.logger.warning("No uploads folder nor true regex defined, "
                                "code execution detection will not be possible. "
                                "(Except for templates with a custom codeExecURL)")
        elif not self.uploadsFolder and self.trueRegex:
            print("No uploads path provided, code detection can still be done "
                  "using true regex capturing group. "
                  "(Except for templates with a custom codeExecURL)")
            cont = input("Do you want to use the True Regex for code execution detection ? [Y/n] ")
            if cont.lower().startswith("y") or cont == "":
                prefixPattern = input("Prefix capturing group of the true regex with: ")
                suffixPattern = input("Suffix capturing group of the true regex with: ")
                self.codeExecUrlPattern = "".join((prefixPattern, "$captGroup$", suffixPattern))
            else:
                self.logger.warning("Code execution detection will not be possible as "
                                    "there is no path nor regex pattern configured. "
                                    "(Except for templates with a custom codeExecURL)")

    # Tries to upload a file through the file upload form.
    def uploadFile(self, suffix, mime, payload,
                   dynamicPayload=False, payloadFilename=None, staticFilename=False):
        with tempfile.NamedTemporaryFile(suffix=suffix) as fd:
            if staticFilename:
                filename = payloadFilename
            else:
                filename = os.path.basename(fd.name)
            filename_wo_ext = filename.split('.', 1)[0]
            if dynamicPayload:
                payload = payload.replace(b"$filename$", bytearray(filename_wo_ext, 'ascii'))
            fd.write(payload)
            fd.flush()
            fd.seek(0)
            if self.shouldLog:
                self.logger.debug("Sending file %s with mime type: %s", filename, mime)
            fileUploadResponse = self.session.post(
                self.uploadUrl,
                files={self.inputName: (filename, fd, mime)},
                data=self.postData
            )
            self.httpRequests += 1
            if self.shouldLog:
                if self.logger.verbosity > 1:
                    printSimpleResponseObject(fileUploadResponse)
                if self.logger.verbosity > 2:
                    print(f"\033[36m{fileUploadResponse}\033[m")

        return (fileUploadResponse, filename, filename_wo_ext)

    # Detects if a given html code represents an upload success or not.
    def isASuccessfulUpload(self, html):
        result = False
        validExt = False
        if self.notRegex:
            fileUploaded = re.search(self.notRegex, html)
            if not fileUploaded:
                result = True
                if self.trueRegex:
                    moreInfo = re.search(self.trueRegex, html)
                    if moreInfo:
                        result = str(moreInfo.groups())
        if self.trueRegex and not result:
            fileUploaded = re.search(self.trueRegex, html)
            if fileUploaded:
                try:
                    result = str(fileUploaded.group(1))
                except:
                    result = str(fileUploaded.group(0))
        return result

    # Callback function for matching html text against regex in order to detect successful uploads
    def detectValidExtension(self, future):
        if not self.stopThreads:
            html = future.result()[0].text
            ext = future.ext[0]

            r = self.isASuccessfulUpload(html)
            if r:
                self.validExtensions.append(ext)
                if self.shouldLog:
                    self.logger.info("\033[1m\033[42mExtension %s seems valid for this form.\033[m", ext)
                    if r != True:
                        self.logger.info("\033[1;32mTrue regex matched the following information: %s\033[m", r)
            return r

    def detectValidExtensions(self, extensions, maxN, extList=None):
        """Detect valid extensions for this upload form (sending legit files with legit mime types)."""
        self.logger.info("### Starting detection of valid extensions ...")
        n = 0
        if extList:
            tmpExtList = []
            for e in extList:
                tmpExtList.append((e, getMime(extensions, e)))
        else:
            tmpExtList = extensions
        validExtensions = []  # unused?

        extensionsToTest = tmpExtList[0:maxN]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            try:
                for ext in extensionsToTest:
                    f = executor.submit(
                        self.uploadFile,
                        "." + ext[0],
                        ext[1],
                        os.urandom(self.size)
                    )
                    f.ext = ext
                    f.add_done_callback(self.detectValidExtension)
                    futures.append(f)
                for future in concurrent.futures.as_completed(futures):
                    a = future.result()
                    n += 1
            except KeyboardInterrupt:
                self.shouldLog = False
                executor.shutdown(wait=False)
                self.stopThreads = True
                executor._threads.clear()
                concurrent.futures.thread._threads_queues.clear()
        return n

    def detectCodeExec(self, url, regex):
        """Detect if a code execution is gained, given an rul to request and a
        regex pattern to match the executed code output.
        """
        if self.shouldLog:
            if self.logger.verbosity > 0:
                self.logger.debug("Requesting %s ...", url)

        r = self.session.get(url)
        if self.shouldLog:
            if r.status_code >= 400:
                self.logger.warning("Code exec detection returned an http code of %s.", r.status_code)
            self.httpRequests += 1
            if self.logger.verbosity > 1:
                printSimpleResponseObject(r)
            if self.logger.verbosity > 2:
                print(f"\033[36m{r.text}\033[m")

        res = re.search(regex, r.text)
        return bool(res)

    def submitTestCase(self, suffix, mime,
                       payload=None, codeExecRegex=None, codeExecURL=None,
                       dynamicPayload=False, payloadFilename=None, staticFilename=False):
        """Generate a temporary file using a suffixed name, a mime type and
        content.  Upload the temp file on the server and eventually try to
        detect if code execution is gained through the uploaded file.
        """
        fu = self.uploadFile(suffix, mime, payload, dynamicPayload, payloadFilename, staticFilename)
        uploadRes = self.isASuccessfulUpload(fu[0].text)
        result = {"uploaded": False, "codeExec": False}
        if not uploadRes:
            return result

        result["uploaded"] = True
        if self.shouldLog:
            self.logger.info("\033[1;32mUpload of '%s' with mime type %s successful\033[m", fu[1], mime)

        if uploadRes is True and self.shouldLog:
            self.logger.info("\033[1;32m\tTrue regex matched the following information: %s\033[m", uploadRes)

        if not codeExecRegex or not valid_regex(codeExecRegex):
            return result

        if self.uploadsFolder or self.trueRegex or codeExecURL:
            url = None
            secondUrl = None
            if self.uploadsFolder or codeExecURL:
                if codeExecURL:
                    filename_wo_ext = fu[2]
                    url = codeExecURL.replace("$uploadFormDir$", os.path.dirname(self.uploadUrl)) \
                                     .replace("$filename$", filename_wo_ext)
                else:
                    url = f"{self.schema}://{self.host}/{self.uploadsFolder}/{fu[1]}"
                filename = fu[1]
                secondUrl = None
                for byte in getPoisoningBytes():
                    if byte in filename:
                        secondUrl = byte.join(url.split(byte)[:-1])
            elif self.codeExecUrlPattern:
                #code exec detection through true regex
                url = self.codeExecUrlPattern.replace("$captGroup$", uploadRes)

            if url:
                executedCode = self.detectCodeExec(url, codeExecRegex)
                if executedCode:
                    result["codeExec"] = True
                    result["url"] = url
            if secondUrl:
                executedCode = self.detectCodeExec(secondUrl, codeExecRegex)
                if executedCode:
                    result["codeExec"] = True
                    result["url"] = secondUrl
        return result

    @staticmethod
    def detectForms(html):
        """Detect HTML forms.

        Returns a list of BeauitifulSoup objects (detected forms).
        """
        soup = BeautifulSoup(html, "html.parser")
        detectedForms = soup.find_all("form")
        returnForms = []
        if detectedForms:
            for f in detectedForms:
                fileInputs = f.findChildren("input", {"type": "file"})
                if fileInputs:
                    returnForms.append((f, fileInputs))
        return returnForms
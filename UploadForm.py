import logging
from utils import *
class UploadForm :
	def __init__(self,notRegex,trueRegex,session,size,postData,uploadsFolder=None) :
		self.logger = logging.getLogger("fuxploider")
		self.postData = postData
		#self.uploadUrl = uploadUrl
		self.session = session
		self.trueRegex = trueRegex
		self.notRegex = notRegex
		#self.inputName = inputName
		self.uploadsFolder = uploadsFolder
		self.size = size
		self.validExtensions = []
	#equivalent de initGet, va cherche le formulaire et détecte l'input file, set les différents éléments
	def setup(self,initUrl) :
		try :
			initGet = self.session.get(initUrl,headers={"Accept-Encoding":None})
			if self.logger.verbosity > 1 :
				printSimpleResponseObject(initGet)
			if self.logger.verbosity > 2 :
				print(initGet.text)
			if initGet.status_code < 200 or initGet.status_code > 300 :
				self.logger.critical("Server responded with following status : %s - %s",initGet.status_code,initGet.reason)
				exit()
		except Exception as e :
				self.logger.critical("%s : Host unreachable (%s)",getHost(initUrl),e)
				exit()
		#récupérer le formulaire,le détecter
		detectedForms = detectForms(initGet.text)
		if len(detectedForms) == 0 :
			self.logger.critical("No HTML form found here")
			exit()
		if len(detectedForms) > 1 :
			self.logger.critical("%s forms found containing file upload inputs, no way to choose which one to test.",len(detectedForms))
			exit()
		if len(detectedForms[0][1]) > 1 :
			self.logger.critical("%s file inputs found inside the same form, no way to choose which one to test.",len(detectedForms[0]))
			exit()

		self.inputName = detectedForms[0][1][0]["name"]
		self.logger.debug("Found the following file upload input : %s",self.inputName)
		formDestination = detectedForms[0][0]
		self.host = getHost(initGet.url)
		self.schema = "https" if initGet.url[0:5] == "https" else "http"
		try :
			self.action = formDestination["action"]
			if self.action == "#" :
				self.uploadUrl = initGet.request.url
			else :
				self.uploadUrl = self.schema+"://"+self.host+"/"+self.action
		except :
			self.uploadUrl = initGet.url
			self.action = self.uploadUrl
		self.logger.debug("Using following URL for file upload : %s",self.uploadUrl)

	def uploadFile(self,suffix,mime,payload) :
		with tempfile.NamedTemporaryFile(suffix=suffix) as fd :
			fd.write(payload)
			fd.flush()
			fd.seek(0)
			filename = os.path.basename(fd.name)
			self.logger.debug("Sending file %s with mime type : %s",filename,mime)
			fu = self.session.post(self.uploadUrl,files={self.inputName:(filename,fd,mime)},data=self.postData)
			if self.logger.verbosity > 1 :
				printSimpleResponseObject(fu)
			if self.logger.verbosity > 2 :
				print(fu.text)
		return (fu,filename)

	def isASuccessfulUpload(self,html) :
		result = False
		validExt = False
		if self.notRegex :
			fileUploaded = re.search(self.notRegex,html)
			if fileUploaded == None :
				result = True
				if self.trueRegex :
					moreInfo = re.search(self.trueRegex,html)
					if moreInfo :
						result = str(moreInfo.groups())
		if self.trueRegex and not result :
			fileUploaded = re.search(self.trueRegex,html)
			if fileUploaded :
				result = str(fileUploaded.groups())
		return result

	def detectValidExtensions(self,extensions,maxN) :
		self.logger.info("### Starting detection of valid extensions ...")
		n = 0
		validExtensions = []
		for ext in extensions :
			validExt = False
			if n < maxN :
				#ext = (ext,mime)
				n += 1
				fu = self.uploadFile("."+ext[0],ext[1],os.urandom(self.size))
				res = self.isASuccessfulUpload(fu[0].text)
				if res :
					self.validExtensions.append(ext[0])
					self.logger.info("\033[1m\033[42mExtension %s seems valid for this form.\033[m", ext[0])
					if res != True :
						self.logger.info("\033[1;32mTrue regex matched the following information : %s\033[m",res)
			else :
				break
		return n
	def detectCodeExec(self,url,regex) :
		if self.logger.verbosity > 0 :
			self.logger.debug("Requesting %s ...",url)
		r = self.session.get(url)
		if self.logger.verbosity > 1 :
			printSimpleResponseObject(r)
		if self.logger.verbosity > 2 :
			print(r.text)
		res = re.search(regex,r.text)
		if res :
			return True
		else :
			return False

	#réponses possibles : ("upload failed", "upload success, impossible de tester l'execution","upload success,execution failed","upload success,execution success")
	def submitTestCase(self,suffix,mime,payload=None,codeExecRegex=None) :
		fu = self.uploadFile(suffix,mime,payload)
		res = self.isASuccessfulUpload(fu[0].text)
		if res :
			self.logger.info("\033[1;32mUpload of '%s' with mime type %s successful\033[m",fu[1], mime)
			if res != True :
				self.logger.info("\033[1;32mTrue regex matched the following information : %s\033[m",res)
		if codeExecRegex and valid_regex(codeExecRegex) :
			if self.uploadsFolder :
				url = self.schema+"://"+self.host+"/"+self.uploadsFolder+"/"+fu[1]
				executedCode = self.detectCodeExec(url,codeExecRegex)
				if executedCode :
					logging.info("\033[1m\033[42mCODE EXECUTED - entry point found\033[m")
				else :
					logging.info("code not executed")
			elif res and res != True and is_url(res) :
				url = res
				print("search "+fu[1]+" inside "+url)
			else :
				print("impossible to determine where to find the uploaded payload")

		'''upload le fichier
		récupérer la réponse
		is réponse successful ?
			si oui
				si true regex match une url ou si uploads folder est set :
					executer payload
						si réponse match la codeExecRegex
							return upload success et code exec success
						sinon
							return upload success et code exec failed
				sinon
					return upload success, impossible de tester code exec
			si non
				return upload failed
		'''
		return
	def detectForms(html) :
		erreur = ""
		soup = BeautifulSoup(html,'html.parser')
		detectedForms = soup.find_all("form")
		returnForms = []
		if len(detectedForms) > 0 :
			for f in detectedForms :
				fileInputs = f.findChildren("input",{"type":"file"})
				if len(fileInputs) > 0 :
					returnForms.append((f,fileInputs))

		return returnForms
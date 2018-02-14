import re,argparse,tempfile,os,requests,signal,sys
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def quitting(signal, frame):
	if input("\nWant to stop ? [y/N] ").lower().startswith("y") :
		sys.exit(0)
	else :
		pass

def valid_url(url) :
	parsedUrl = urlparse(url)
	if parsedUrl.scheme != "" and parsedUrl.netloc != "" :
		return url
	else :
		return False

def valid_proxyString(proxyString) :
	exp = re.compile("^(?:(https?):\/\/)?(?:(.+?):(.+?)@)?([A-Za-z0-9\_\-\~\.]+)(?::([0-9]+))?$")
	r = exp.match(proxyString)
	if r :
		return {"username":r.group(2),"password":r.group(3),"protocol":r.group(1),"hostname":r.group(4),"port":r.group(5)}
	else :
		raise argparse.ArgumentTypeError("Proxy information must be like \"[user:pass@]host:port\". Example : \"user:pass@proxy.host:8080\".")
def valid_regex(regex) :
	try :
		re.compile(regex)
	except re.error :
		raise argparse.ArgumentTypeError("The given regex argument does not look like a valid regular expression.")
	return regex
def is_regex(regex) :
	try :
		re.compile(regex)
		return True
	except re.error :
		return False
def valid_proxyCreds(creds) :
	exp = re.compile("^([^\n\t :]+):([^\n\t :]+)$")
	r = exp.match(creds)
	if r :
		return {"username":r.group(1),"password":r.group(2)}
	else :
		raise argparse.ArgumentTypeError("Proxy credentials must follow the next format : 'user:pass'. Provided : '"+creds+"'")

def valid_nArg(n) :
	if int(n) > 0 :
		return n
	else :
		raise argparse.ArgumentTypeError("Positive integer expected.")
def valid_postData(data) :
	exp = re.compile("([^=&?\n]*=[^=&?\n]*&?)+")
	if exp.match(data) :
		return data
	else :
		raise argparse.ArgumentTypeError("Additionnal POST data must be written like the following : 'key1=value1&key2=value2&...'")
def getHost(url) :
	exp = re.compile("^(https?\:\/\/)((([\da-z\.-]+)\.([a-z\.]{2,6}))|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(:[0-9]+)?([\/\w \.-]*)\/?([\/\w \.-]*)\/?((\?|&).+?(=.+?)?)*$")
	res = exp.match(url)
	return str(res.group(2))
def postDataFromStringToJSON(params) :
	if params != None :
		prePostData = params.split("&")
		postData = {}
		for d in prePostData :
			p = d.split("=")
			postData[p[0]] = p[1]
		return postData
	else :
		return {}

def getFormInputs(html) :
	soup = BeautifulSoup(html,'html.parser')
	inputs = soup.find__all("input")

def detectForms(html) :
	erreur = ""
	soup = BeautifulSoup(html,'html.parser')
	detectedForms = soup.find_all("form")
	returnForms = []
	if len(detectedForms) > 0 :
		for f in detectedForms :
			fileInputs = f.findChildren("input",{"type":re.compile("file",re.I)})
			if len(fileInputs) > 0 :
				returnForms.append((f,fileInputs))

	return returnForms
def getMime(extensions,ext) :
	for e in extensions :
		if e[0] == ext :
			return e[1]

def getResource(url) :
	exp = re.compile("^(https?\:\/\/)((([\da-z\.-]+)\.([a-z\.]{2,6}))|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(:[0-9]+)?([\/\w \.-]*)\/?([\/\w \.-]*)\/?((\?|&).+?(=.+?)?)*$")
	r = exp.match(url)
	z = r.group(7).split('/')
	return z[len(z)-1]

def loadExtensions(loadFrom,filepath="mimeTypes.advanced") :
	ext = []
	if loadFrom == "file" :
		with open(filepath, "r") as fd :
			#ext = [(ext,mime)]
			ext = []
			for e in fd :
				e = e[:-1]
				ligne = e.split(" ")
				mime = ligne[0]
				for z in ligne[1:] :
					ext.append((z,mime))
	elif type(loadFrom) == type([]) :
		for askedExt in loadFrom :
			with open(filepath, "r") as fd :
				for e in fd :
					e = e[:-1]
					ligne = e.split(" ")
					mime = ligne[0]

					if askedExt in ligne :
						ext.append((askedExt,mime))
	else :
		pass

	return ext

def addProxyCreds(initProxy,creds) :
	httpproxy = initProxy["http"]
	httpsproxy = initProxy["https"]
	if re.match("^http\://.*",httpproxy) :
		httpproxy = "http://"+creds[0]+":"+creds[1]+"@"+httpproxy[7:]
	else :
		httpproxy = "http://"+creds[0]+":"+creds[1]+"@"+httpproxy

	if re.match("^https\://.*",httpsproxy) :
		httpsproxy = "https://"+creds[0]+":"+creds[1]+"@"+httpsproxy[8:]
	else :
		httpsproxy = "https://"+creds[0]+":"+creds[1]+"@"+httpsproxy
	newProxies = {"http":httpproxy,"https":httpsproxy}
	return newProxies

def printSimpleResponseObject(resObject) :
	print("\033[36m"+resObject.request.method+" - "+resObject.request.url+" : "+str(resObject.status_code)+"\033[m")
	printFormattedHeaders(resObject.headers)
def printFormattedHeaders(headers) :
	for key in headers.keys() :
		print("\033[36m"+"\t- "+str(key)+" : "+str(headers[key])+"\033[m")

def getPoisoningBytes() :
	return ["%00"]
	#return ["%00",":",";"]
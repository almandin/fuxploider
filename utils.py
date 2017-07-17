import re,argparse,random,string
from bs4 import BeautifulSoup

def valid_url(url) :
	exp = re.compile("^(https?\:\/\/)((([\da-z\.-]+)\.([a-z\.]{2,6}))|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(:[0-9]+)?([\/\w \.-]*)\/?([\/\w \.-]*)\/?((\?|&).+?(=.+?)?)*$")
	if exp.match(url) :
		return url
	else :
		raise argparse.ArgumentTypeError("Le type de paramètre attendu est une URL valide")
		return False

def valid_regex(regex) :
	try :
		re.compile(regex)
	except re.error :
		raise argparse.ArgumentTypeError("Le type de paramètre attendu est une expression régulière valide")
	return regex
def valid_postData(data) :
	exp = re.compile("([^=&?\n]*=[^=&?\n]*&?)+")
	if exp.match(data) :
		return data
	else :
		raise argparse.ArgumentTypeError("Les données POST doivent être écrites sous la forme 'key1=value1&key2=value2&...'")
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
			fileInputs = f.findChildren("input",{"type":"file"})
			if len(fileInputs) > 0 :
				returnForms.append((f,fileInputs))

	return returnForms

def getResource(url) :
	exp = re.compile("^(https?\:\/\/)((([\da-z\.-]+)\.([a-z\.]{2,6}))|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(:[0-9]+)?([\/\w \.-]*)\/?([\/\w \.-]*)\/?((\?|&).+?(=.+?)?)*$")
	r = exp.match(url)
	z = r.group(7).split('/')
	return z[len(z)-1]


def randomFileNameGenerator(size=8, chars=string.ascii_uppercase + string.digits + string.ascii_lowercase) :
	return ''.join(random.choice(chars) for _ in range(size))

def loadExtensions(filepath="mime.types") :
	with open(filepath, "r") as fd :
		#ext = {"jpg":"application/jpeg",...}
		ext = {}
		for e in fd :
			e = e[:-1]
			ligne = e.split(" ")
			mime = ligne[0]
			for z in ligne[1:] :
				ext[z] = mime
	return ext
#!/usr/bin/python3
import re,requests,argparse,sys,logging,os,coloredlogs,datetime
from html.parser import HTMLParser
from bs4 import BeautifulSoup
from utils import *


coloredlogs.install(fmt='%(asctime)s %(levelname)s - %(message)s', level=logging.INFO,datefmt='[%m/%d/%Y-%H:%M:%S]')
logging.getLogger("requests").setLevel(logging.ERROR)

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--data", dest="data", help="Additionnal data to be transmitted via POST method. Example : -d \"key1=value1&key2=value2\"", type=valid_postData)
requiredNamedArgs = parser.add_argument_group('Required named arguments')
requiredNamedArgs.add_argument("-u","--url", dest="url",required=True, help="Web page URL containing the file upload form to be tested. Example : http://test.com/index.html?action=upload", type=valid_url)
requiredNamedArgs.add_argument("--not-regexp", help="Regex matching an upload failure", type=valid_regex, required=True,dest="notRegexp")

args = parser.parse_args()

print("""\033[1;32m
                                     
 ___             _     _   _         
|  _|_ _ _ _ ___| |___|_|_| |___ ___ 
|  _| | |_'_| . | | . | | . | -_|  _|
|_| |___|_,_|  _|_|___|_|___|___|_|  
            |_|                      

\033[1m\033[42m{version 0.1}\033[m

\033[m[!] legal disclaimer : Usage of fuxploider for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
	""")

now = datetime.datetime.now()
print("[*] starting at "+str(now.hour)+":"+str(now.minute)+":"+str(now.second))

postData = postDataFromStringToJSON(args.data)
tempFolder = "/tmp"

s = requests.Session()
try :
	initGet = s.get(args.url,headers={"Accept-Encoding":None})
	if initGet.status_code < 200 or initGet.status_code > 300 :
		logging.critical("Server responded with following status : %s - %s",initGet.status_code,initGet.reason)
		exit()
except Exception as e :
	logging.critical("%s : Host unreachable",getHost(args.url))
	exit()

detectedForms = detectForms(initGet.text)

if len(detectedForms) == 0 :
	logging.critical("No HTML form found here")
	exit()
if len(detectedForms) > 1 :
	logging.critical("%s forms found containing file upload inputs, no way to choose which one to test.",len(detectedForms))
	exit()
if len(detectedForms[0][1]) > 1 :
	logging.critical("%s file inputs found inside the same form, no way to choose which one to test.",len(detectedForms[0]))
	exit()

fileInput = detectedForms[0][1][0]
formDestination = detectedForms[0][0]
try :
	action = formDestination["action"]
	schema = "https" if initGet.url[0:5] == "https" else "http"
	host = getHost(initGet.url)
	uploadURL = schema+"://"+host+action
except :
	uploadURL = initGet.url



extensions = loadExtensions("mime.types")
extensionsMalveillantes = ["php","asp"]


###### DETECTION DES EXTENSIONS VALIDES POUR CE FORMULAIRE ######
logging.info("Starting detection of valid extensions ...")
extensionsAcceptees = []
for ext in extensions.keys() :
	logging.info("Trying extension %s", ext)
	filename = randomFileNameGenerator()+"."+ext
	fullpath = tempFolder+"/"+filename
	open(fullpath,"wb").close()
	fd = open(fullpath,"rb")
	fu = s.post(uploadURL,files={fileInput["name"]:(filename,fd,extensions[ext])},data=postData)
	fd.close()
	os.remove(fullpath)

	fileUploaded = re.search(args.notRegexp,fu.text)
	if fileUploaded == None :
		logging.info("\033[1m\033[42mExtension %s seems valid for this form.\033[m", ext)
		extensionsAcceptees.append(ext)
#################################################################


def techniques(legitExt,badExt,extensions) :
	retour = []
	#retour.append(("filename.extension1.extension2","mime/type"))
	retour.append((randomFileNameGenerator()+"."+legitExt+"."+badExt,extensions[legitExt]))
	retour.append((randomFileNameGenerator()+"."+legitExt+"."+badExt,extensions[badExt]))
	retour.append((randomFileNameGenerator()+"."+badExt+"."+legitExt,extensions[legitExt]))
	retour.append((randomFileNameGenerator()+"."+badExt+"."+legitExt,extensions[badExt]))
	retour.append((randomFileNameGenerator()+"."+legitExt+"%00."+badExt,extensions[legitExt]))
	retour.append((randomFileNameGenerator()+"."+legitExt+"%00."+badExt,extensions[badExt]))
	retour.append((randomFileNameGenerator()+"."+badExt+"%00."+legitExt,extensions[legitExt]))
	retour.append((randomFileNameGenerator()+"."+badExt+"%00."+legitExt,extensions[badExt]))

	return retour

for legitExt in list(set(extensions) & set(extensionsAcceptees)) :
	for badExt in extensionsMalveillantes :
		#files = [("nom.ext","mime"),("nom.ext","mime")]
		files = techniques(legitExt,badExt,extensions)
		for f in files :
			filename = f[0]
			mime = f[1]
			fullpath = tempFolder+"/"+filename
			open(fullpath,"wb").close()
			logging.info("Trying file '%s' with mimetype '%s'.",filename,mime)
			fd = open(fullpath,"rb")
			fu = s.post(uploadURL,files={fileInput["name"]:(filename,fd,mime)},data=postData)
			fd.close()
			os.remove(fullpath)
			fileUploaded = re.search(args.notRegexp,fu.text)
			if fileUploaded == None :
				logging.info("\033[1m\033[42mFile '%s' uploaded with success using a mime type of '%s'.\033[m",filename,mime)
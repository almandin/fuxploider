#!/usr/bin/python3
import re,requests,argparse,sys,logging,os
from html.parser import HTMLParser
from bs4 import BeautifulSoup
from utils import *
logging.basicConfig(level=logging.WARNING,format='%(asctime)s %(levelname)s - %(message)s',datefmt='[%m/%d/%Y-%H:%M:%S]')
logging.getLogger("requests").setLevel(logging.ERROR)

parser = argparse.ArgumentParser(description="Detects file upload vulnerabilities given an URL")
parser.add_argument("URL", nargs=1, help="Url de la page contenant le formulaire à tester. Exemple : http://test.fr/index.html?action=upload", type=valid_url)
parser.add_argument("--data", help="Données à transmettre par post en plus du fichier à uploader. Exemple : 'name=test&aaa=bbb'", type=valid_postData)
parser.add_argument("errReg", help="Regex matchant un échec d'upload", type=valid_regex)

args = parser.parse_args()
args.URL = args.URL[0]

postData = postDataFromStringToJSON(args.data)
tempFolder = "/tmp"

s = requests.Session()
try :
	initGet = s.get(args.URL,headers={"Accept-Encoding":None})
	if initGet.status_code < 200 or initGet.status_code > 300 :
		logging.critical("URL injoignable (%s -> %s)",args.url,initGet.status_code)
		exit()
except :
	logging.critical("%s : Hôte injoignable",getHost(args.URL))
	exit()

detectedForms = detectForms(initGet.text)

if len(detectedForms) == 0 :
	logging.critical("Aucun formulaire html détecté sur cette URL.")
	exit()
if len(detectedForms) > 1 :
	logging.critical("%s formulaires contenant des champs d'upload de fichiers trouvés, impossible de choisir lequel utiliser.",len(detectedForms))
	exit()
if len(detectedForms[0][1]) > 1 :
	logging.critical("%s champs d'upload de fichiers découverts dans le même formulaire, impossible de choisir lequel tester.",len(detectedForms[0]))
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
extensionsAcceptees = []
for ext in extensions.keys() :
	logging.info("Trying extension "+ext)
	filename = randomFileNameGenerator()+"."+ext
	fullpath = tempFolder+"/"+filename
	open(fullpath,"wb").close()
	fd = open(fullpath,"rb")
	fu = s.post(uploadURL,files={fileInput["name"]:(filename,fd,extensions[ext])},data=postData)
	fd.close()
	os.remove(fullpath)

	fileUploaded = re.search(args.errReg,fu.text)
	if fileUploaded == None :
		logging.warning("Extension "+ext+" acceptée !")
		extensionsAcceptees.append(ext)
#################################################################
print(extensionsAcceptees)


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
			logging.info("Trying file "+filename+" with mimetype "+mime)
			fd = open(fullpath,"rb")
			fu = s.post(uploadURL,files={fileInput["name"]:(filename,fd,mime)},data=postData)
			fd.close()
			os.remove(fullpath)
			fileUploaded = re.search(args.errReg,fu.text)
			if fileUploaded == None :
				logging.warning("Fichier "+filename+" accepté avec le type mime "+mime)
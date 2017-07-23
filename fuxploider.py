#!/usr/bin/python3
import re,requests,argparse,logging,os,coloredlogs,datetime,getpass,tempfile
from utils import *


coloredlogs.install(fmt='%(asctime)s %(levelname)s - %(message)s', level=logging.INFO,datefmt='[%m/%d/%Y-%H:%M:%S]')
logging.getLogger("requests").setLevel(logging.ERROR)

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--data", metavar="postData",dest="data", help="Additionnal data to be transmitted via POST method. Example : -d \"key1=value1&key2=value2\"", type=valid_postData)
parser.add_argument("--proxy", metavar="proxyUrl", dest="proxy", help="Proxy information. Example : --proxy \"user:password@proxy.host:8080\"", type=valid_proxyString)
parser.add_argument("--proxy-creds",metavar="credentials",nargs='?',const=True,dest="proxyCreds",help="Prompt for proxy credentials at runtime. Format : 'user:pass'",type=valid_proxyCreds)
parser.add_argument("-n",metavar="n",nargs=1,default=["100"],dest="n",help="Number of common extensions to use. Example : -n 100")
requiredNamedArgs = parser.add_argument_group('Required named arguments')
requiredNamedArgs.add_argument("-u","--url", metavar="target", dest="url",required=True, help="Web page URL containing the file upload form to be tested. Example : http://test.com/index.html?action=upload", type=valid_url)
requiredNamedArgs.add_argument("--not-regex", metavar="regex", help="Regex matching an upload failure", type=valid_regex, required=True,dest="notRegex")

args = parser.parse_args()

if args.proxyCreds and args.proxy == None :
	parser.error("--proxy-creds must be used with --proxy.")
args.n = int(args.n[0])

print("""\033[1;32m
                                     
 ___             _     _   _         
|  _|_ _ _ _ ___| |___|_|_| |___ ___ 
|  _| | |_'_| . | | . | | . | -_|  _|
|_| |___|_,_|  _|_|___|_|___|___|_|  
            |_|                      

\033[1m\033[42m{version 0.1}\033[m

\033[m[!] legal disclaimer : Usage of fuxploider for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
	""")
if args.proxyCreds == True :
	args.proxyCreds = {}
	args.proxyCreds["username"] = input("Proxy username : ")
	args.proxyCreds["password"] = getpass.getpass("Proxy password : ")

now = datetime.datetime.now()
mimeFiles = "mimeTypes.advanced"

print("[*] starting at "+str(now.hour)+":"+str(now.minute)+":"+str(now.second))

postData = postDataFromStringToJSON(args.data)

s = requests.Session()
s.trust_env = False
if args.proxy :
	if args.proxy["username"] and args.proxy["password"] and args.proxyCreds :
		logging.warning("Proxy username and password provided by the --proxy-creds switch replaces credentials provided using the --proxy switch")
	if args.proxyCreds :
		proxyUser = args.proxyCreds["username"]
		proxyPass = args.proxyCreds["password"]
	else :
		proxyUser = args.proxy["username"]
		proxyPass = args.proxy["password"]
	proxyProtocol = args.proxy["protocol"]
	proxyHostname = args.proxy["hostname"]
	proxyPort = args.proxy["port"]
	proxy = ""
	if proxyProtocol != None :
		proxy += proxyProtocol+"://"
	else :
		proxy += "http://"

	if proxyUser != None and proxyPass != None :
		proxy += proxyUser+":"+proxyPass+"@"

	proxy += proxyHostname
	if proxyPort != None :
		proxy += ":"+proxyPort

	if proxyProtocol == "https" :
		proxies = {"https":proxy}
	else :
		proxies = {"http":proxy,"https":proxy}

	s.proxies.update(proxies)

try :
	initGet = s.get(args.url,headers={"Accept-Encoding":None})
	if initGet.status_code < 200 or initGet.status_code > 300 :
		logging.critical("Server responded with following status : %s - %s",initGet.status_code,initGet.reason)
		exit()
except Exception as e :
		logging.critical("%s : Host unreachable (%s)",getHost(args.url),e)
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
	uploadURL = schema+"://"+host+"/"+action
except :
	uploadURL = initGet.url



extensions = loadExtensions(mimeFiles)
nastyExtensions = ["php","asp"]


###### VALID EXTENSIONS DETECTION FOR THIS FORM ######
logging.info("### Starting detection of valid extensions ...")
n = 0
validExtensions = []
for ext in extensions :
	if n < args.n :
		#ext = (ext,mime)
		n += 1
		logging.info("Trying extension %s", ext[0])
		with tempfile.NamedTemporaryFile(suffix="."+ext[0]) as fd :
			fu = s.post(uploadURL,files={fileInput["name"]:(os.path.basename(fd.name),fd,ext[1])},data=postData)
		fileUploaded = re.search(args.notRegex,fu.text)
		if fileUploaded == None :
			logging.info("\033[1m\033[42mExtension %s seems valid for this form.\033[m", ext[0])
			validExtensions.append(ext[0])
	else :
		break
logging.info("### Tried %s extensions, %s are valid.",n,len(validExtensions))

#################################################################
logging.info("### Starting messing with file extensions and mime types...")
#still looking for a more pythonic way to do this ...
def techniques(legitExt,badExt,extensions) :
	filesToTry = []
	#filesToTry.append(("filename.extension1.extension2","mime/type"))
	filesToTry.append(("."+legitExt+"."+badExt,getMime(extensions,legitExt)))
	filesToTry.append(("."+legitExt+"."+badExt,getMime(extensions,badExt)))
	filesToTry.append(("."+badExt+"."+legitExt,getMime(extensions,legitExt)))
	filesToTry.append(("."+badExt+"."+legitExt,getMime(extensions,badExt)))
	filesToTry.append(("."+legitExt+"%00."+badExt,getMime(extensions,legitExt)))
	filesToTry.append(("."+legitExt+"%00."+badExt,getMime(extensions,badExt)))
	filesToTry.append(("."+badExt+"%00."+legitExt,getMime(extensions,legitExt)))
	filesToTry.append(("."+badExt+"%00."+legitExt,getMime(extensions,badExt)))

	return filesToTry

suceededAttemps = []
toutesLesExtensions = [x[0] for x in extensions]

intersect = list(set(toutesLesExtensions) & set(validExtensions))

for legitExt in intersect :
	for badExt in nastyExtensions :
		#files = [("nom.ext","mime"),("nom.ext","mime")]
		files = techniques(legitExt,badExt,extensions)
		for f in files :
			fileSuffix = f[0]
			mime = f[1]
			filename=""
			with tempfile.NamedTemporaryFile(suffix=fileSuffix) as fd :
				logging.info("Trying file '%s' with mimetype '%s'.",os.path.basename(fd.name),mime)
				fu = s.post(uploadURL,files={fileInput["name"]:(os.path.basename(fd.name),fd,mime)},data=postData)
				filename = os.path.basename(fd.name)
			fileUploaded = re.search(args.notRegex,fu.text)
			if fileUploaded == None :
				logging.info("\033[1m\033[42mFile '%s' uploaded with success using a mime type of '%s'.\033[m",filename,mime)
				suceededAttemps.append((filename,mime))

print("End of detection phase, the following files have been uploaded meaning a potential file upload vulnerability :")
print(suceededAttemps)
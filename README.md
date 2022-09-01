# Bypass Fuzzer
The original bypassfuzzer.py :)

Fuzz 401/403ing endpoints for bypasses


This tool performs various checks via headers, path normalization, verbs, etc. to attempt to bypass ACL's or URL validation.

It will output the response codes and length for each request, in a nicely organized, color coded way so things are reaable.

I implemented a "Smart Filter" that lets you mute responses that look the same after a certain number of times.

You can now feed it raw HTTP requests that you save to a file from Burp.

#### Follow me on twitter! @intrudir
<br>

- [Bypass Fuzzer](#bypass-fuzzer)
      - [Follow me on twitter! @intrudir](#follow-me-on-twitter-intrudir)
- [Usage](#usage)
  - [Basic examples](#basic-examples)
    - [Feed it a raw HTTP request from Burp!](#feed-it-a-raw-http-request-from-burp)
  - [Smart filter feature!](#smart-filter-feature)
  - [Specify cookies to use in requests:](#specify-cookies-to-use-in-requests)
  - [Specify a method/verb and body data to send](#specify-a-methodverb-and-body-data-to-send)
  - [Specify custom headers to use with every request](#specify-custom-headers-to-use-with-every-request)
  - [Specify a proxy to use](#specify-a-proxy-to-use)
  - [Skip sending header payloads or url payloads](#skip-sending-header-payloads-or-url-payloads)
  - [Hide response code/length](#hide-response-codelength)
- [TODO](#todo)


---
# Usage
```bash
usage: bypassfuzzer.py [-h] [-u URL] [-m {GET,POST,PUT,PATCH,DELETE}] [-d DATA_PARAMS] [-c COOKIES] [-H HEADER] [-r REQUEST] [-p PROXY] [-hc HC] [-hl HL] [-sf] [-sh] [-su] [-std]
                       [--export-endpoints EXPORT_ENDPOINTS]

use this script to fuzz endpoints that return a 401/403

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Specify the target URL
  -m {GET,POST,PUT,PATCH,DELETE}, --method {GET,POST,PUT,PATCH,DELETE}
                        Specify the HTTP method/verb
  -d DATA_PARAMS, --data DATA_PARAMS
                        Specify data to send with the request.
  -c COOKIES, --cookies COOKIES
                        Specify cookies to use in requests. (e.g., --cookies "cookie1=blah; cookie2=blah")
  -H HEADER, --header HEADER
                        Add headers to your request (e.g., --header "Accept: application/json" --header "Host: example.com"
  -r REQUEST, --request REQUEST
                        Load a text file with a HTTP request in it for fuzzing (e.g., --request req.txt
  -p PROXY, --proxy PROXY
                        Specify a proxy to use for requests (e.g., http://127.0.0.1:8080)
  -hc HC                Hide response code from output, single or comma separated
  -hl HL                Hide response length from output, single or comma separated
  -sf, --smart          Enable the smart filter
  -sh, --skip-headers   Skip testing bypass headers
  -su, --skip-urls      Skip testing path payloads
  -std, --skip-td       Skip testing trailing dot attack
  --export-endpoints EXPORT_ENDPOINTS
                        Saves endpoints with payloads to a file
```
<br>

## Basic examples
```bash
python3 bypassfuzzer.py -u http://example.com/test1/test2/test3/forbidden.html
```
<br>

### Feed it a raw HTTP request from Burp!
Simply add the request to a file and run the script!

![image](https://user-images.githubusercontent.com/24526564/188021983-2f38bac0-c144-45ce-9a45-3db32470a136.png)


NOTE: using `-u` is required, but be aware that whatever endpoint you have passed here will get overwritten by the endpoint in your request file.
```bash
bypassfuzzer.py -u https://example.com/forbidden -r request.txt
```
<br>

## Smart filter feature!
Based on response code and length. If it sees a response 8 times or more it will automatically mute it.

Repeats are changeable in the code until I add an option to specify it in flag

NOTE: Can't be used simultaneously with `-hc` or `-hl` (yet)

```bash
# toggle smart filter on
bypassfuzzer.py -u https://example.com/forbidden --smart
```
<br>

## Specify cookies to use in requests:
(minus the cookie header name)  

some examples:
```bash
--cookies "cookie1=blah"
-c "cookie1=blah; cookie2=blah"
```
<br>

## Specify a method/verb and body data to send
```bash
bypassfuzzer.py -u https://example.com/forbidden -m POST -d "param1=blah&param2=blah2"
bypassfuzzer.py -u https://example.com/forbidden -m PUT -d "param1=blah&param2=blah2"
```
<br>

## Specify custom headers to use with every request
Maybe you need to add some kind of auth header like `Authorization: bearer <token>`

Specify `-H "header: value"` for each additional header you'd like to add:
```bash
bypassfuzzer.py -u https://example.com/forbidden -H "Some-Header: blah" -H "Authorization: Bearer 1234567"
```
<br>

## Specify a proxy to use
Useful if you wanna proxy through Burp
```bash
bypassfuzzer.py -u https://example.com/forbidden --proxy http://127.0.0.1:8080
```
<br>

## Skip sending header payloads or url payloads
```bash
# skip sending headers payloads
bypassfuzzer.py -u https://example.com/forbidden -sh
bypassfuzzer.py -u https://example.com/forbidden --skip-headers

# Skip sending path normailization payloads
bypassfuzzer.py -u https://example.com/forbidden -su
bypassfuzzer.py -u https://example.com/forbidden --skip-urls
```
<br>

## Hide response code/length
Provide comma delimited lists without spaces.
Examples:
```bash
# Hide response codes
bypassfuzzer.py -u https://example.com/forbidden -hc 403,404,400  

# Hide response lengths of 638
bypassfuzzer.py -u https://example.com/forbidden -hl 638  
```
<br>

# TODO
- [ ] Automatically check other methods/verbs for bypass
- [x] absolute domain attack
- [ ] Looking for ideas. Ping me on twitter! @intrudir

# Bypass Fuzzer
The original 403fuzzer.py :)

Fuzz 401/403ing endpoints for bypasses

This tool performs various checks via headers, path normalization, verbs, etc. to attempt to bypass ACL's or URL validation.

It will output the response codes and length for each request, in a nicely organized, color coded way so things are reaable.

I implemented a "Smart Filter" that lets you mute responses that look the same after a certain number of times.

You can now feed it raw HTTP requests that you save to a file from Burp.

#### Follow me on twitter! @intrudir

---
# Usage
```bash
usage: bypassfuzzer.py -h
```
## Specifying a request to test
### Best method: Feed it a raw HTTP request from Burp!
Simply paste the request into a file and run the script!  
- It will parse and use `cookies` & `headers` from the request.
- Easiest way to authenticate for your requests
```bash
python3 bypassfuzzer.py -r request.txt
```
![image](https://user-images.githubusercontent.com/24526564/188021983-2f38bac0-c144-45ce-9a45-3db32470a136.png)

### Using other flags
**Specify a URL**
```bash
python3 bypassfuzzer.py -u http://example.com/test1/test2/test3/forbidden.html
```

**Specify cookies to use in requests:**  
some examples:
```bash
--cookies "cookie1=blah"
-c "cookie1=blah; cookie2=blah"
```

**Specify a method/verb and body data to send**
```bash
bypassfuzzer.py -u https://example.com/forbidden -m POST -d "param1=blah&param2=blah2"
bypassfuzzer.py -u https://example.com/forbidden -m PUT -d "param1=blah&param2=blah2"
```

**Specify custom headers to use with every request**
Maybe you need to add some kind of auth header like `Authorization: bearer <token>`

Specify `-H "header: value"` for each additional header you'd like to add:
```bash
bypassfuzzer.py -u https://example.com/forbidden -H "Some-Header: blah" -H "Authorization: Bearer 1234567"
```

## Smart filter feature!
Based on response code and length. If it sees a response 8 times or more it will automatically mute it.

Repeats are changeable in the code until I add an option to specify it in flag

**NOTE: Can't be used simultaneously with `-hc` or `-hl` (yet)**

```bash
# toggle smart filter on
bypassfuzzer.py -u https://example.com/forbidden --smart
```

## Specify a proxy to use
Useful if you wanna proxy through Burp
```bash
bypassfuzzer.py -u https://example.com/forbidden --proxy http://127.0.0.1:8080
```

## Skip sending header payloads or url payloads
```bash
# skip sending headers payloads
bypassfuzzer.py -u https://example.com/forbidden -sh
bypassfuzzer.py -u https://example.com/forbidden --skip-headers

# Skip sending path normailization payloads
bypassfuzzer.py -u https://example.com/forbidden -su
bypassfuzzer.py -u https://example.com/forbidden --skip-urls
```

## Hide response code/length
Provide comma delimited lists without spaces.
Examples:
```bash
# Hide response codes
bypassfuzzer.py -u https://example.com/forbidden -hc 403,404,400  

# Hide response lengths of 638
bypassfuzzer.py -u https://example.com/forbidden -hl 638  
```

# TODO
- [x] Automatically check other methods/verbs for bypass
- [x] absolute domain attack
- [ ] Add HTTP/2 support
- [ ] Looking for ideas. Ping me on twitter! @intrudir

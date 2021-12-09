# Writing Performant Signatures

## Profiling
In order to identify whether a signature is performant or not, you'll need to profile it. To do this, you need to build suricata with profiling enabled. The default profiling log filename is `rule_perf.log`. When testing performance, it is important to test your signatures against a pcap that is representative of the traffic in your network.

The signatures in `rule_perf.log` will be sorted by "ticks", "average ticks", "average ticks (match)", "average ticks (no match)", "number of checks", "number of matches", or "max ticks", or all of the above depending on your `suricata.yaml` config. A good place to start is looking at signatures sorted by ticks since this will show the overall worst performing signatures. You can use command line tools to make this information more easily readable:

```
user@laptop:~$ cat rule_perf.log |jq -c 'select(.sort=="ticks")' |jq .
```

When profiling your signatures, pay attention to the "checks" and "matches" values. These values can be used to tell what proportion of packets passed the initial prefiltering and needed further evaluation. A high "checks" value could indicate a need to better prefilter using `content` (if no content term exists already), `fast_pattern` or `prefilter`.

## Content Terms
Whenever possible, make sure your rule has a `content` term. Suricata uses `content` terms to prefilter arriving packets, reducing the number of signatures that need further evaluation for a given packet. If a signature has a `content` term and that term isn't found anywhere in a packet, it doesn't matter how expensive the rest of the signature is since it won't be checked.

### fast_pattern

Suricata uses an [algorithm](https://suricata.readthedocs.io/en/latest/rules/fast-pattern-explained.html) to determine the best content term to use for prefiltering. Sometimes, suricata picks a less ideal content term to prefilter on. In these cases, you should use [fast_pattern](https://suricata.readthedocs.io/en/latest/rules/prefilter-keywords.html#fast-pattern) to force suricata to prefilter using the term that you specify. Consider the below signature:

```
alert tcp any any -> any any (\
        msg:"LetsGo_yahoosb simple rule beacon";\
        content:"User-Agent: ";\
        content:"(host:"; distance:5; fast_pattern;\
        content:",ip:"; distance:5;\
        reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
        metadata:file BIN_LetsGo_yahoosb_b21ba443726385c11802a8ad731771c0_2011-07-19.pcap;\
        sid:50;\
        rev:1;\
        )
```

Without `fast_pattern`, this signature peformed poorly. Likely, the rules engine decided that "User-Agent: " was the best pattern to use, which resulted in very poor performance in an environment with any reasonable amount of HTTP traffic. `fast_pattern` significantly reduced the number of packets that this rule had to be evaluated against.

### prefilter
If you don't have a content term in your signature, you can specify another field to prefilter on. You can check what keywords allow the use of the `prefilter` on your installation by running `suricata --list-keywords=all`. On my installation, the below keywords are supported:

```bash
user@laptop:~$ suricata --list-keywords=all |grep -B2 prefilter |grep "^[a-zA-Z]" |tr ":" " "
app-layer-protocol 
tcp.ack 
tcp.seq 
tcp.flags 
fragbits 
fragoffset 
ttl 
itype 
icode 
icmp_id 
icmp_seq 
dsize 
flow 
id 
template2 
icmpv6.mtu 
tcp.mss 
```


If all else fails, you may consider prefiltering using dsize and an appropriate maximum or minimum packet size. Even when the packet size may not be known precisely, a reasonable dsize can exclude sessions consisting of very small or very large packets.

Note: In testing, I found that using `app-layer-protocol: http` with regular content matches would result in no alerts. Using `alert http ...` with a regular content match produced the expected output, and was comparable performance to using `http` and `http.uri`. When a protocol is supported in the [rule header](https://suricata.readthedocs.io/en/latest/rules/intro.html#protocol), you should use this instead of `app-layer-protocol`.

## Application Parsers
Consider the following two signatures:

```
alert tcp any any -> any any (\
	msg:"Pingbed simple rule";\
	content:"GET /default.htm HTTP/1.1|0d 0a|"; offset:0; depth:27;\
	content:"User-Agent: Windows+NT+5.1|0d 0a|"; distance:0; within: 100;\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file Pingbed_74fc916a0187f3d491ef9fb0b540f228.pcap;\
	sid:1;\
	rev:1;\
)
```

```
alert http any any -> any any (\
	msg:"Pingbed suricata rule";\
	http.user_agent; content:"Windows+NT+5.1";\
	http.uri; content:"default.htm";\
	reference:url,https://contagiodump.blogspot.com/2013/04/collection-of-pcap-files-from-malware.html;\
	metadata:file Pingbed_74fc916a0187f3d491ef9fb0b540f228.pcap;\
	sid:2;\
	rev:1;\
)
```

While the signatures differ slightly in their implementation, they are both alerting on the same malicious traffic. The signatures themselves take approximately the same number of ticks to evaluate, but the signature using the HTTP application parser takes approximately 50% of the simple rule's `ticks_total` because it only has to check against HTTP traffic. See below for some profiling I did on the two signatures.

```
...
    {
      "signature_id": 1,
      "gid": 1,
      "rev": 1,
      "checks": 38,
      "matches": 38,
      "ticks_total": 1436328,
      "ticks_max": 58752,
      "ticks_avg": 37798,
      "ticks_avg_match": 37798,
      "ticks_avg_nomatch": 0,
      "percent": 0
    },
    {
      "signature_id": 2,
      "gid": 1,
      "rev": 1,
      "checks": 21,
      "matches": 19,
      "ticks_total": 763128,
      "ticks_max": 54576,
      "ticks_avg": 36339,
      "ticks_avg_match": 37222,
      "ticks_avg_nomatch": 27954,
      "percent": 0
    }
...
```

If you try to combine two application layer protocol keywords, suricata will log an error for the signature. This happens even if the keywords refer to the same protocol. An example is a `alert http ...` rule with `app-layer-protocol: http`.

## Lua

Running any extra code on your packets will have a negative performance impact, but sometimes you need more functionality than what is supported by suricata keywords. Lua allows a signature writer to run arbitrary lua code against different buffers. See suricata's [Lua Scripting](https://suricata.readthedocs.io/en/latest/rules/rule-lua-scripting.html) section for more details. Suricata supports passing through the following buffers to a lua script:
```
    packet – entire packet, including headers
    payload – packet payload (not stream)
    buffer – the current sticky buffer
    http.uri
    http.uri.raw
    http.request_line
    http.request_headers
    http.request_headers.raw
    http.request_cookie
    http.request_user_agent
    http.request_body
    http.response_headers
    http.response_headers.raw
    http.response_body
    http.response_cookie
```

Any time your signature touches lua, there will be a non-zero cost regardless of how complex the lua script is. Consider the following rule and corresponding lua:

```
alert ip any any -> any any (msg:"All payloads lua"; lua:lua-test-all.lua; sid:1; rev:1;)

-------
function init(args)
        local needs = {}
        needs["payload"] = tostring(true)
        return needs
end

function match(args)
        return 1
end 
```

On my test infrastructure, this rule cost an average of approximately 20500 ticks to run:

```
...
  "rules": [
    {
      "signature_id": 1,
      "gid": 1,
      "rev": 1,
      "checks": 590439,
      "matches": 335564,
      "ticks_total": 12092973156,
      "ticks_max": 10575540,
      "ticks_avg": 20481,
      "ticks_avg_match": 21892,
      "ticks_avg_nomatch": 18623,
      "percent": 42
    },
...
```

### Lua Best Practices
- Don't use lua unless it is absolutely necessary
- Narrow down the signature as much as possible using suricata keywords
- Validate your input before performing expensive operations on it
- Avoid loops whenever possible
- Fail fast: quick checks early on to bail out of processing
- Include a default `return 0` to handle edge cases that fall through
- Include unit tests to validate the match() function. This will make your code more maintainable.

### Narrow Down Your Signature
Consider the signature below:
```
alert tcp any any -> any any (msg:"Bad malware"; content:"|ab cd|"; offset:45; depth:2; lua:badmalware.lua; sid:1; rev:1;)
```

Even if the lua code is very precise, depending on the traffic that makes up your network it could be doing a lot of work on sessions that could be filtered out by suricata.

You should consider narrowing down the traffic using dsize, app-layer-proto, stream_size, etc. in order to reduce the amount of times that the lua code will be executed.

```
app-layer-proto:failed;
app-layer-proto:!tls;
dsize:<80;
dsize:>45;
stream_size:client, <, 100;
```

### Validate Your Input
If you expect a buffer to be a certain size, check that it is the expected size before you do something expensive using it. For example, if a buffer should contain a 16 byte encryption key, make sure that the buffer is 16 bytes before you try to decrypt with it.

### Avoid Loops Whenever Possible
Looping over a buffer of unknown size introduces unknown latencies. If using a loop, you need to be extra careful to ensure an infinite loop is impossible.

### Fail Fast
Using two identical rules, one that performs a busyloop in lua and one the other that returns 0 immediately, the busy loop takes approximately twice as many ticks than the quick return.
```
-- Busy loop
function match(args)
        local i = 10000

        while i > 0 do
                i = i - 1
        end
        return 0
end

-- Quick
function match(args)
        return 0
end
```

```
  "rules": [
    {
      "signature_id": 1,
      "checks": 590439,
      "matches": 0,
      "ticks_total": 21203433288,
      "ticks_max": 20055852,
      "ticks_avg": 35911,
      "ticks_avg_match": 0,
      "ticks_avg_nomatch": 35911,
      "percent": 65
    },
    {
      "signature_id": 2,
      "checks": 590439,
      "matches": 0,
      "ticks_total": 11015156808,
      "ticks_max": 11417436,
      "ticks_avg": 18655,
      "ticks_avg_match": 0,
      "ticks_avg_nomatch": 18655,
      "percent": 34
    }
  ]
```

## Decode Events

Sometimes you want to write a rule that only matches on some sort of mangled packets. For example, a packet that has a bad checksum. These keywords aren't very well documented, but you can find examples in the [decoder-events.rules](https://github.com/OISF/suricata/blob/master/rules/decoder-events.rules) file that is shipped with the suricata source, as well as the source code in [decode-events.c](https://github.com/OISF/suricata/blob/master/src/decode-events.c) and [detect-csum.c](https://github.com/OISF/suricata/blob/master/src/detect-csum.c). These keywords are all in the format of `decode-event: ...;` or `<protocol>-csum:invalid;`. See below examples from [decoder-events.rules](https://github.com/OISF/suricata/blob/master/rules/decoder-events.rules):

```
alert icmp any any -> any any (msg:"SURICATA ICMPv4 invalid checksum"; icmpv4-csum:invalid; classtype:protocol-command-decode; sid:2200076; rev:2;)
alert pkthdr any any -> any any (msg:"SURICATA TCP packet too small"; decode-event:tcp.pkt_too_small; classtype:protocol-command-decode; sid:2200033; rev:2;)
```

## Appendix A: Weird Behaviour

While writing this guide, I've come across some strange suricata behaviour that I can't explain. For example, the two rules below should be equivalent:

```
alert ip any any -> any any (msg:"dsize > 0"; dsize:>0; sid:1; rev:1;)
alert ip any any -> any any (msg:"Lua payload size > 0"; lua:lua-test-payload-size.lua; sid:2; rev:1;)

-- lua-test-payload-size.lua
function init(args) 
        local needs = {}
        needs["payload"] = tostring(true)
        return needs
end

function match(args)
        a = tostring(args["payload"])
        if #a > 0 then
                return 1
        end
        return 0
end

```

Yet, when I run these two rules across a sample pcap file, I get the following:
```
"rules": [
    {
      "signature_id": 2,
      "gid": 1,
      "rev": 1,
      "checks": 590457,
      "matches": 335564,
      ...
    },
    {
      "signature_id": 1,
      "gid": 1,
      "rev": 1,
      "checks": 335564,
      "matches": 334762,
      ...
    }

```
Adding a `ip_proto:!6` to exclude all TCP and there is no discrepancy, so there are some approximately 800 packets in my test pcap where the simple lua script calculates a length differently than dsize.

## Appendix B: Gotchas

### Flowint
When using `flowint: name, =, <value>`, it seems to set the value of the flowint to `<value>` instead of testing for equality. If you want to test for a specific flowint value (eg. 10), you can use: `flowint: name, >, 9; flowint: name, <, 11`.

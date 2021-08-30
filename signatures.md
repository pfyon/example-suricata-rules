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

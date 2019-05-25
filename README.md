# DNS-based Public Suffix List handling for Python

This Python package provides a `PSL` class for [querying the Public
Suffix List (PSL)](https://publicsuffix.zone/) via the DNS. By utilizing
the library, one can retrieve information about the public suffix
status of a domain as well as the PSL rules governing it. There is also
a corresponding command-line tool, `psl-dns_query`, enabling convenient
use of the library from the shell.

Public suffix information is based on DNS lookups only; no rule
matching is performed at lookup time. To make this possible, the PSL
rules have been encoded in the DNS itself (currently under the
DNSSEC-enabled zone `query.publicsuffix.zone`). This facilitates easy
querying without the need to keep the PSL at hand. The PSL zone is
maintained by [SSE](https://securesystems.de/) and usually updated once
a day.

The `Parser` class (along with the `psl-dns_parse` command) is used to
iterate over a [PSL file](https://publicsuffix.org/list/public_suffix_list.dat)
and convert the ruleset into a list of DNS Resource Record sets for
submission to the DNS operator. The tool adds an extra `TXT` record at
the root of the PSL zone, containing the parsing timestamp as well as
the PSL file SHA-256 hash for currentness checking.

The package also contains the `psl-dns_check` command (based on the
`Checker` class) to iterate over a PSL file and query the DNS for each
rule encountered, to verify whether the PSL zone contents are in
agreement with the file. (Note that DNS caching may cause update
delays; after a zone update, you may be receiving outdated information
until the TTL of the PSL DNS records expires. To make sure, specify one
of the PSL zone's authoritative servers as the `resolver` argument.)

**Note:** DNS resolvers learn about the domains that get queried, so
depending on the use case, using this service may not be up to your
privacy standards. It is possible though to set up a private copy of
the query zone and configure a local resolver to avoid query leaks.

## Usage

### Python
The following examples show how to query the PSL via DNS using the
`PSL` class. For advanced use, please refer to the source.

Example use cases for the `Parser` and `Checker` classes can be found
in the scripts under `psl/commands/`.

#### Initialize
```python
>>> from psl_dns import PSL
>>> psl = PSL()
```

#### Query public suffix status of a domain (for the rules, see below)
```python
>>> psl.is_public_suffix('com')
True
>>> psl.is_public_suffix('checkip.dedyn.io')
False
>>> psl.is_public_suffix('takatsu.kawasaki.jp')
True
>>> psl.is_public_suffix('www.ikuoufukushi.takatsu.kawasaki.jp')
False
>>> psl.is_public_suffix('city.kawasaki.jp')
False
>>> psl.is_public_suffix('www.library.city.kawasaki.jp')
False
```

#### Get the public suffix for a domain
```python
>>> psl.get_public_suffix('com')
'com'
>>> psl.get_public_suffix('checkip.dedyn.io')
'dedyn.io'
```

The following examples are based on PSL wildcard rules. Wildcard labels
are expanded into the respective labels of the domain of interest:

```python
>>> psl.get_public_suffix('takatsu.kawasaki.jp')  # Wildcard *.kawasaki.jp
'takatsu.kawasaki.jp'
>>> psl.get_public_suffix('www.ikuoufukushi.takatsu.kawasaki.jp')  # same
'takatsu.kawasaki.jp'
>>> psl.get_public_suffix('city.kawasaki.jp')  # Wildcard exception
'jp'
>>> psl.get_public_suffix('www.library.city.kawasaki.jp')  # same
'jp'
```

If the queried domain has a trailing dot, the dot is preserved in the
response. Furthermore, IDDA mode is preserved so that Unicode queries
return Unicode responses, and Punycode queries return Punycode responses:

```python
>>> psl.get_public_suffix('www.xn--55qx5d.cn')
'xn--55qx5d.cn'
>>> psl.get_public_suffix('www.公司.cn.')
'公司.cn.'
```

#### Get the set of rules applicable for a domain
```python
>>> psl.get_rules('com')
{'com'}
>>> psl.get_rules('checkip.dedyn.io')
{'dedyn.io'}
>>> psl.get_rules('takatsu.kawasaki.jp')
{'*.kawasaki.jp'}
>>> psl.get_rules('www.ikuoufukushi.takatsu.kawasaki.jp')
{'*.kawasaki.jp'}
>>> psl.get_rules('city.kawasaki.jp') # Note wildcard exception
{'jp', '!city.kawasaki.jp', '*.kawasaki.jp'}
>>> psl.get_rules('www.library.city.kawasaki.jp') # same
{'jp', '!city.kawasaki.jp', '*.kawasaki.jp'}
```

Rules are always returned in Unicode encoding and without a trailing
dot, consistent with the encoding in the Public Suffix List itself:

```python
>>> psl.get_rules('www.xn--55qx5d.cn.')
{'公司.cn'}
```

#### Rules with inline wildcards
Unfortunately, rules with inline wildcard labels `*` (i.e. wildcards
that are not at the leftmost position) cannot be represented using DNS
lookups. Luckily, the PSL does not contain any such rules as of the
time of this writing (but this may change).

To demonstrate what would happen in such a case, a few test rules have
been added to the PSL zone under the `*.wildcard.test` domain. (As
these rules are made up, they are not included in the PSL checksum
calculation.)

When querying the public suffix (status) for a domain that falls into
the realm of a wildcard label which acts as an inline label in at
least one PSL rule, an `UnsupportedRule` exception is thrown:

```python
# Query public suffix status
>>> psl.is_public_suffix('unsupported.wildcard.test')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  ...
    raise UnsupportedRule
psl.exceptions.UnsupportedRule: Domain unsupported.wildcard.test is affected by an unsupported rule

# Get the public suffix
>>> psl.get_public_suffix('unsupported.wildcard.test')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  ...
    raise UnsupportedRule
psl.exceptions.UnsupportedRule: Domain unsupported.wildcard.test is affected by an unsupported rule
```

However, you can retrieve the relevant rules for manual consumption:

```python
# Get the applicable rules
>>> psl.get_rules('unsupported.wildcard.test')
{'*.wildcard.test', '!except.inline.*.wildcard.test', 'inline.*.wildcard.test', '*.inline.*.wildcard.test'}
```

This behavior applies to the entire DNS subtree that is defined by the
first (right-most) wildcard label in the rule.


### Command line

#### psl-dns_query
This is a command-line interface to the `PSL` class demonstrated in the
previous section.

```sh
$ psl-dns_query -h
usage: psl-dns_query [-h] [--zone ZONE] [--resolver RESOLVER]
                     [--timeout TIMEOUT] [-l] [-c] [-v]
                     domain

Query the PSL via DNS and check the PSL status of a domain.

Returns the the word "public" or "private", followed by the public
suffix that covers the queried domain. IDNA mode and trailing dots
(if given) are preserved.

Public Suffix List (PSL) rules with inline wildcards are not fully
supported. If the queried name is governed by such a rule, the word
"unknown" is returned.

Optionally, the set of applicable rules and the PSL checksum can be
displayed.

Exit codes: 0 (public), 1 (private), or 2 (unknown).

positional arguments:
  domain               Domain to query

optional arguments:
  -h, --help           show this help message and exit
  --zone ZONE          PSL zone to use (default: query.publicsuffix.zone)
  --resolver RESOLVER  DNS resolver to use instead of system resolver
                       (default: None)
  --timeout TIMEOUT    DNS query timeout (seconds) (default: 5)
  -l                   Show set of applicable rules (default: False)
  -c                   Show PSL checksum (default: False)
  -v, --verbose        Increase output verbosity (default: 0)
```

##### Retrieve status and public suffix
```sh
# Plain
$ psl-dns_query com
public com

# Same, followed by the set of relevant rules, in no particular order
$ psl-dns_query www.ck -l
private *
*.ck
!www.ck
*
```

#### psl-dns_parse
```sh
$ psl-dns_parse -h
usage: psl-dns_parse [-h] [--zone ZONE] [--format FORMAT] [-l] [-v] psl_file

Print rules from a Public Suffix List (PSL) file in DNS RRsets format.

positional arguments:
  psl_file         Path to PSL file

optional arguments:
  -h, --help       show this help message and exit
  --zone ZONE      PSL zone to use (default: query.publicsuffix.zone)
  --format FORMAT  Output format to use (default: deSEC)
  -l               List available formats (default: False)
  -v, --verbose    Increase output verbosity (default: 0)
```

##### Convert current PSL file to deSEC RRsets
```sh
# Note: This produces very long output
$ time psl-dns_parse <(curl https://publicsuffix.org/list/public_suffix_list.dat) | jq .
[
  {
    "subname": "ac",
    "ttl": 86400,
    "type": "PTR",
    "records": [
      "ac."
    ]
  },
  ... # shortened for readability
  {
    "subname": "",
    "ttl": 86400,
    "type": "TXT",
    "records": [
      "\"1555895008 d205f587d61c6bbf05bec818776da1dd030ce68f2e8912fea732158b9a33cc54\""
    ]
  }
]

real	0m1.262s
user	0m0.475s
sys	0m0.239s
```

#### psl-dns_check
```sh
$ psl-dns_check -h
usage: psl-dns_check [-h] [--resolver RESOLVER] [--timeout TIMEOUT]
                     [--zone ZONE] [-v]
                     psl_file

Check rules from the Public Suffix List (PSL) via DNS and output
inconsistencies.

positional arguments:
  psl_file             Path to PSL file

optional arguments:
  -h, --help           show this help message and exit
  --resolver RESOLVER  DNS resolver to use instead of system resolver
                       (default: None)
  --timeout TIMEOUT    DNS query timeout (in seconds) (default: 5)
  --zone ZONE          PSL zone to use (default: query.publicsuffix.zone)
  -v, --verbose        Increase output verbosity (default: 0)
```

##### Verifying the correctness of the PSL zone
```sh
$ time psl-dns_check -v <(curl https://publicsuffix.org/list/public_suffix_list.dat)
... # shortened for readability
INFO:psl:Querying for zone.id.query.publicsuffix.zone. TXT
INFO:psl:Querying for zone.id.query.publicsuffix.zone. PTR
INFO:psl:Querying for query.publicsuffix.zone. TXT
WARNING:psl:Hash mismatch! Input PSL file appears to differ from remote version.
8684 rules with 3 inconsistencies found

real	13m42.366s
user	0m38.560s
sys	0m8.383s
```

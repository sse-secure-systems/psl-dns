import argparse
import sys
import textwrap

from psl_dns import PSL
from psl_dns.exceptions import UnsupportedRule
from psl_dns.providers import DefaultProvider
from psl_dns.utils import CustomFormatter


def main():
    description = '''
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
        '''
    parser = argparse.ArgumentParser(description=textwrap.dedent(description), formatter_class=CustomFormatter)
    parser.add_argument('domain', help='Domain to query', type=str)
    parser.add_argument('--zone', default=DefaultProvider.ZONE, help='PSL zone to use', type=str)
    parser.add_argument('--resolver', default=None, help='DNS resolver to use instead of system resolver', type=str)
    parser.add_argument('--timeout',  default=5, help='DNS query timeout (seconds)', type=int)
    parser.add_argument("-l", action='store_true', help="Show set of applicable rules")
    parser.add_argument("-c", action='store_true', help="Show PSL checksum")
    parser.add_argument("-v", '--verbose', help="Increase output verbosity", action="count", default=0)
    args = parser.parse_args()

    psl = PSL(zone=args.zone, resolver=args.resolver, timeout=args.timeout, log_level=args.verbose)

    domain = args.domain
    try:
        public_suffix = psl.get_public_suffix(domain)
    except UnsupportedRule:
        print('unknown')
        status = 2
    else:
        is_public_suffix = psl.is_public_suffix(domain, public_suffix)
        print('{} {}'.format('public' if is_public_suffix else 'private', public_suffix))
        status = int(not is_public_suffix)

    if args.l:
        for rule in psl.get_rules(domain):
            print(rule)

    if args.c:
        print(psl.get_checksum())

    sys.exit(status)


if __name__ == "__main__":
    main()

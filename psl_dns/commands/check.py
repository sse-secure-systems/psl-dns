import argparse
import codecs

from psl_dns import Checker
from psl_dns.providers import DefaultProvider


def main():
    description = 'Check rules from the Public Suffix List (PSL) via DNS and output inconsistencies.'
    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('psl_file', help='Path to PSL file', type=str)
    parser.add_argument('--resolver', default=None, help='DNS resolver to use instead of system resolver', type=str)
    parser.add_argument('--timeout', default=5, help='DNS query timeout (in seconds)', type=int)
    parser.add_argument('--zone', default=DefaultProvider.ZONE, help='PSL zone to use', type=str)
    parser.add_argument("-v", "--verbose", help="Increase output verbosity", action="count", default=0)
    args = parser.parse_args()

    checker = Checker(zone=args.zone, resolver=args.resolver, timeout=args.timeout, log_level=args.verbose)
    with codecs.open(args.psl_file, 'r', 'utf8') as stream:
        checker.process(stream)
    checker.verify_checksum()

    print('{} rules with {} inconsistencies found'.format(checker.n, len(checker.errors)))
    for error in checker.errors:
        print('Rule {} not in {}'.format(error[0], error[1]))


if __name__ == "__main__":
    main()

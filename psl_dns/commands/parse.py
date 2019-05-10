import argparse
import codecs
import json
import textwrap

from psl_dns import Parser
from psl_dns.providers import DefaultProvider
from psl_dns.utils import CustomFormatter

EXTRA_RULES = [
    '*.wildcard.test',
    'inline.*.wildcard.test',
    '*.inline.*.wildcard.test',
    '!except.inline.*.wildcard.test',
]


def main():
    description = '''
        Print rules from a Public Suffix List (PSL) file as DNS RRsets suitable
        for a submission to a DNS provider.
        '''
    parser = argparse.ArgumentParser(description=textwrap.dedent(description), formatter_class=CustomFormatter)
    parser.add_argument('psl_file', help='Path to PSL file', type=str)
    parser.add_argument('--zone', default=DefaultProvider.ZONE, help='PSL zone to use', type=str)
    parser.add_argument('--provider', default=DefaultProvider.Parser.variety, help='Provider to use', type=str)
    parser.add_argument('-l', action='store_true', help='List available formats')
    parser.add_argument("-v", "--verbose", help="Increase output verbosity", action="count", default=0)
    args = parser.parse_args()

    # Print available providers
    if args.l:
        print('Available output formats (default *):')
        for variety in Parser.get_varieties():
            bullet = '*' if variety == DefaultProvider.Parser.variety else '-'
            print('{} {}'.format(bullet, variety))
        return

    # Initialize parser
    parser_class = Parser.variety_class(args.provider)
    parser = parser_class(zone=args.zone, log_level=args.verbose)

    with codecs.open(args.psl_file, 'r', 'utf8') as stream:
        parser.process(stream)

    for rule in EXTRA_RULES:
        parser.process_line(rule, update_hash=False)

    rrsets = parser.get_rrsets()
    print(json.dumps(rrsets))


if __name__ == "__main__":
    main()

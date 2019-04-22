import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query

from psl.base import PSLBase
from psl.exceptions import UnsupportedRule
from psl.providers import DefaultProvider


class PSL(PSLBase):
    ptr_cache = {}

    def __init__(self, resolver, zone=DefaultProvider.ZONE, timeout=5, *args, **kwargs):
        self.resolver = resolver
        self.timeout = timeout
        self.zone = zone.rstrip('.') + '.'
        super().__init__(*args, **kwargs)

    def get_checksum(self):
        rrset = self.query('', dns.rdatatype.TXT)
        if rrset is None:
            return None

        return rrset.items[0].to_text().strip('"').split(' ')[1]

    def get_rules(self, domain):
        # For wildcard exceptions and unsupported inline wildcards, the rules
        # are given as TXT records. Otherwise, it's just the public suffix.
        # TODO This probably can be optimzed by factor ~2 using ANY QTYPE.
        rrset = self.query(domain, dns.rdatatype.TXT)
        if rrset:
            rules = [item.to_text().strip('"') for item in rrset]
        else:
            rules = [self.get_public_suffix(domain).rstrip('.')]

        return {str(rule.encode('utf-8'), 'idna') for rule in rules}

    def get_public_suffix(self, domain):
        if not domain.rstrip('.'):
            raise ValueError('Invalid domain name')

        # Query DNS if necessary
        if domain not in self.ptr_cache:
            self.ptr_cache[domain] = self.query(domain, dns.rdatatype.PTR)
        else:
            self.logger.debug('Using PTR cache for {}'.format(domain))

        # Retrieve RRset
        rrset = self.ptr_cache[domain]
        if rrset is None:
            msg = 'Domain {} is affected by an unsupported rule'.format(domain)
            raise UnsupportedRule(msg)

        # Extract
        public_suffix = rrset.items[0].to_text()
        if domain[-1] != '.':
            public_suffix = public_suffix[:-1]

        return public_suffix

    def is_public_suffix(self, domain, raise_exception=True):
        try:
            public_suffix = self.get_public_suffix(domain)
        except UnsupportedRule:
            if not raise_exception:
                return False
            raise

        return (domain.count('.') == public_suffix.count('.'))

    def query(self, domain, rdatatype):
        # Construct and normalize QNAME
        qname = '.'.join([domain.rstrip('.'), self.zone]).lstrip('.')
        qname = dns.name.from_text(qname)
        self.logger.info('Querying for {} {}'.format(qname, dns.rdatatype.to_text(rdatatype)))

        # Query PSL
        query = dns.message.make_query(qname, rdatatype)
        r = dns.query.tcp(query, self.resolver, timeout=self.timeout)

        # Follow CNAMEs
        while True:
            rrset = r.get_rrset(r.answer, qname, dns.rdataclass.IN, dns.rdatatype.CNAME)
            if rrset is None:
                break
            self.logger.debug('Following CNAME to {}'.format(rrset.items[0].to_text()))
            qname = dns.name.from_text(rrset.items[0].to_text())

        # Extract and return RRset
        return r.get_rrset(r.answer, qname, dns.rdataclass.IN, rdatatype)

import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query

from psl_dns.base import PSLBase
from psl_dns.exceptions import UnsupportedRule
from psl_dns.providers import DefaultProvider


class PSL(PSLBase):
    _cache = {}

    def __init__(self, resolver, zone=DefaultProvider.ZONE, timeout=5, *args, **kwargs):
        self.resolver = resolver
        self.timeout = timeout
        self.zone = zone.rstrip('.') + '.'
        super().__init__(*args, **kwargs)

    def _retrieve(self, qname, rdatatype):
        key = (qname, rdatatype)
        if not self._cache.get(key):
            self.logger.info('Querying for {} {}'.format(qname, dns.rdatatype.to_text(rdatatype)))
            query = dns.message.make_query(qname, rdatatype)
            self._cache[key] = dns.query.tcp(query, self.resolver, timeout=self.timeout)
        return self._cache[key]

    def get_checksum(self):
        rrset = self.query('', dns.rdatatype.TXT)
        if rrset is None:
            return None

        return rrset.items[0].to_text().strip('"').split(' ')[1]

    def _get_public_suffix_raw(self, domain):
        # Retrieve RRset
        rrset = self.query(domain, dns.rdatatype.PTR)

        # '.' is a dummy value for the unsupported case. It corresponds to the
        # empty rule and therefore cannot appear on the PSL.
        if rrset is None:
            msg = 'Domain {} is affected by an unsupported rule'.format(domain)
            raise UnsupportedRule(msg)

        return rrset.items[0].to_text()

    def get_public_suffix(self, domain):
        if domain[0] == '.':
            raise ValueError('Invalid domain name')

        public_suffix = self._get_public_suffix_raw(domain)

        # Extract
        if domain[-1] != '.':
            public_suffix = public_suffix[:-1]

        # Replace wildcard labels with the corresponding labels from the domain (punycode)
        punycode_domain = domain.encode('idna').decode('ascii')
        domain_labels = punycode_domain.split('.')
        domain_labels.reverse()
        public_labels = public_suffix.split('.')
        public_labels.reverse()

        for i, domain_label, public_label in zip(range(len(public_labels)), domain_labels, public_labels):
            if public_label == '*':
                public_labels[i] = domain_label
            elif public_label != domain_label.encode('idna').decode('ascii'):
                raise ValueError(
                    'Public suffix label {} inconsistent with domain label {}'.format(public_label, domain_label))

        public_labels.reverse()
        public_suffix = '.'.join(public_labels)

        # Return in initial encoding
        punycode = (domain == punycode_domain)
        return public_suffix if punycode else public_suffix.encode('ascii').decode('idna')

    def get_rules(self, domain):
        # The public suffix rule itself is always a rule
        try:
            rules = [self._get_public_suffix_raw(domain).rstrip('.')]
        except UnsupportedRule:
            rules = []

        # For wildcard exceptions and unsupported inline wildcards, additional rules
        # are given as TXT records.
        rrset = self.query(domain, dns.rdatatype.TXT)
        if rrset:
            rules.extend([item.to_text()[1:-1] for item in rrset])

        return {str(rule.encode('utf-8'), 'idna') for rule in rules}

    def is_public_suffix(self, domain, public_suffix=None):
        public_suffix = public_suffix or self.get_public_suffix(domain)
        return (domain.count('.') == public_suffix.count('.'))

    def query(self, domain, rdatatype):
        # Normalize, then construct QNAME, and retrieve response
        qname = '.'.join([domain.rstrip('.'), self.zone]).lstrip('.')
        qname = dns.name.from_text(qname)
        r = self._retrieve(qname, rdatatype)

        # Follow CNAMEs
        while True:
            rrset = r.get_rrset(r.answer, qname, dns.rdataclass.IN, dns.rdatatype.CNAME)
            if rrset is None:
                break
            self.logger.debug('Following CNAME to {}'.format(rrset.items[0].to_text()))
            qname = dns.name.from_text(rrset.items[0].to_text())

        # Extract and return RRset
        return r.get_rrset(r.answer, qname, dns.rdataclass.IN, rdatatype)

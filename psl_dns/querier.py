import dns.rdatatype
import dns.resolver

from psl_dns import exceptions
from psl_dns.base import PSLBase
from psl_dns.providers import DefaultProvider


class PSL(PSLBase):
    def __init__(self, resolver=None, zone=DefaultProvider.ZONE, timeout=None, *args, **kwargs):
        super().__init__(*args, **kwargs)

        use_system_nameservers = resolver is None
        self.resolver = dns.resolver.Resolver(configure=use_system_nameservers)
        if not use_system_nameservers:
            self.resolver.nameservers = [resolver]
        self.timeout = timeout
        self.zone = zone.rstrip('.') + '.'

    def get_checksum(self):
        answer = self.query('', dns.rdatatype.TXT)
        if not len(answer):
            return None

        return answer[0].to_text().strip('"').split(' ')[1]

    def _get_public_suffix_raw(self, domain):
        # Retrieve RRset
        try:
            answer = self.query(domain, dns.rdatatype.PTR)
        except dns.resolver.NoAnswer:
            msg = 'Domain {} is affected by an unsupported rule'.format(domain)
            raise exceptions.UnsupportedRule(msg)

        return answer[0].to_text()

    def get_public_suffix(self, domain):
        if domain[0] == '.':
            raise ValueError('Invalid domain name')

        # Get public suffix and normalize
        public_suffix = self._get_public_suffix_raw(domain)
        if domain[-1] != '.':
            public_suffix = public_suffix[:-1]

        # Replace wildcard labels with the corresponding labels from the domain (punycode)
        punycode_domain = domain.encode('idna').decode('ascii')
        domain_labels = punycode_domain.split('.')
        domain_labels.reverse()
        public_labels = public_suffix.split('.')
        public_labels.reverse()

        for i, domain_label, public_label in zip(range(len(public_labels)), domain_labels, public_labels):
            domain_label = domain_label.lower()
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
        except exceptions.UnsupportedRule:
            rules = []

        # For wildcard exceptions and unsupported inline wildcards, additional rules
        # are given as TXT records.
        try:
            rules.extend([rr.to_text()[1:-1] for rr in self.query(domain, dns.rdatatype.TXT)])
        except dns.resolver.NoAnswer:
            pass

        return {str(rule.encode('utf-8'), 'idna') for rule in rules}

    def is_public_suffix(self, domain, public_suffix=None):
        public_suffix = public_suffix or self.get_public_suffix(domain)
        return domain.count('.') == public_suffix.count('.')

    def query(self, domain, rdatatype):
        # Normalize, then construct QNAME, and retrieve response
        qname = '.'.join([domain.lower().rstrip('.'), self.zone]).lstrip('.')
        qname = dns.name.from_text(qname)
        self.logger.info('Querying for {} {}'.format(qname, dns.rdatatype.to_text(rdatatype)))
        try:
            answer = self.resolver.query(qname, rdatatype, lifetime=self.timeout)
        except dns.resolver.NXDOMAIN:
            message = 'Cannot find {} {} record. (Resolver claims NXDOMAIN. Are you using a non-compliant resolver?)'
            message = message.format(qname, dns.rdatatype.to_text(rdatatype))
            raise exceptions.ResolverError(message)
        return answer

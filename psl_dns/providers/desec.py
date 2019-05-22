from psl_dns.parser import Parser as AbstractParser

TTL = 86400
ZONE = 'query.publicsuffix.zone'


class Parser(AbstractParser):
    variety = 'deSEC'  # https://desec.io/

    def __init__(self, *args, **kwargs):
        self.ttl = kwargs.pop('ttl', TTL)
        self.zone = kwargs.get('zone') or ZONE
        super().__init__(*args, **kwargs)

    def _update_rrsets(self, subname, contents):
        rrsets = []
        for content in contents:
            rdatatype, data = content
            if type(data) == str:
                suffix = ('.' + self.zone) if rdatatype == 'CNAME' else ''
                data = [data + suffix]
            if rdatatype != 'TXT':
                data = ['{}.'.format(v) for v in data]
            rrsets.append({'subname': subname, 'ttl': self.ttl, 'type': rdatatype, 'records': data})
        self.rrsets.update({subname: rrsets})

    def get_rrsets(self):
        if not self.rrsets:
            self._process()

        return [rrset for rrset_list in self.rrsets.values() for rrset in rrset_list]


Parser.register()

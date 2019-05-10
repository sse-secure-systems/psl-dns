import logging

from psl_dns.parser import PSLReader
from psl_dns import PSL


class Checker(PSLReader):
    def __init__(self, *args, **kwargs):
        self.errors = []
        self.n = 0
        self.psl = PSL(*args, **kwargs)
        super().__init__(*args, **kwargs)

    def process_line(self, line):
        self.update_hash(line)

        rule = self.get_rule_from_line(line)
        if rule is None:
            return

        self.n += 1
        domain = rule.lstrip('!').encode('idna').decode('ascii')
        rules = self.psl.get_rules(domain)
        in_sync = rule in rules

        msg = '{} maps to rules {}'.format(rule, rules)
        self.logger.log(logging.DEBUG if in_sync else logging.INFO, msg)

        if not in_sync:
            self.errors.append((rule, rules))

        return in_sync

    def verify_checksum(self):
        match = (self.get_checksum() == self.psl.get_checksum())

        if not match:
            msg = 'Hash mismatch! Input PSL file appears to differ from remote version.'
            self.logger.warning(msg)

        return match

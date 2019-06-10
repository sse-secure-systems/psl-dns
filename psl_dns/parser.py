from collections import defaultdict
import hashlib
import time

from psl_dns.base import PSLBase


class VarietyClass:
    # https://softwareengineering.stackexchange.com/a/352254/334328
    variety = None
    variety_versions = {}

    @classmethod
    def get_varieties(cls):
        return cls.variety_versions.keys()

    @classmethod
    def register(cls):
        Parser.variety_versions[cls.variety] = cls

    @classmethod
    def variety_class(cls, variety):
        try:
            return cls.variety_versions[variety]
        except KeyError:
            raise NotImplementedError('Variety not implemented: {}'.format(variety))


class PSLReader(PSLBase):
    def __init__(self, *args, **kwargs):
        self.m = hashlib.sha256()
        super().__init__(*args, **kwargs)

    def get_checksum(self):
        return self.m.hexdigest()

    @staticmethod
    def get_rule_from_line(line):
        candidate = line.strip()
        if not candidate or candidate.startswith('//'):
            return None

        return candidate.lower()

    def process(self, stream_reader):
        line = stream_reader.readline()
        while line:
            self.process_line(line)
            line = stream_reader.readline()

    def process_line(self, line):
        raise NotImplementedError

    def update_hash(self, string):
        self.m.update(bytearray(string, 'utf8'))


class Parser(VarietyClass, PSLReader):
    # Initialize rule categories
    regular_rules = []
    wildcard_exception_rules = []
    proper_wildcard_rules = []
    inline_wildcard_rules = []

    # RRsets will go here
    rrsets = {}

    def _add_root_rule(self):
        self._update_rrsets('*', [('PTR', '*')])

    def _fix_wildcard_shadowing(self):
        # We have added a lot of records. Because wildcard DNS records at the root of a non-empty
        # subtree do only apply at the level that they have been defined at (and not below, see
        # https://tools.ietf.org/html/rfc4592#section-3.3.1), some wildcards will have their scope
        # limited due to the presence of other rule records at lower level. PSL rules, however,
        # apply to all their subnames (until it collides with a more specific rule).
        # 
        # To take this into account, we apply the following steps for each record:
        # 
        # - First, add a child wildcard record (*.<record>), so that the rule defined by the record
        #   also applies to all subnames. (If <record> is already a wildcard, we skip this step.)
        # 
        # - We then start traversing the tree upward, adding more child wildcard records along the
        #   way. The first of these extends the rule of the parent to all sister names of <record>
        #   which do not have an explicit rule defined.
        #   If we find that the intermediate name itself does not have an explicit role, we also
        #   add an explicit link to its direct parent. This is necessary because the node, being an
        #   intermediate name without records ("empty non-terminal"), does actually exist on the
        #   DNS level and would therefore shadow any higher-level wildcard. For details, see
        #   https://tools.ietf.org/html/rfc4592#section-2.2.2.
        # 
        # - We then repeat the previous step for each remaining level towards the root of the tree.
        #   Each step causes the rule of the next-higher level to take effect on the current level.
        # 
        # - Once names with single labels (like "com") have been processed, we stop. All undefined
        #   sister names are already covered by the "*". rule.
        # 
        # Example: "s3.dualstack.eu-west-1.amazonaws.com" leads to multiple rule chains:
        # 1) *.s3.dualstack.eu-west-1.amazonaws.com --> s3.dualstack.eu-west-1.amazonaws.com
        # 2) *.dualstack.eu-west-1.amazonaws.com --> dualstack.eu-west-1.amazonaws.com
        #    --> eu-west-1.amazonaws.com --> amazonaws.com --> com
        # 3) On each level of 2, we also need a wildcard that serves as a lateral entrypoint.

        for rule in list(self.rrsets):
            # Check if work is to be done, i.e. rule does not have an RRset or needs a child wildcard
            wildcard = '*.{}'.format(rule)
            while rule is not None and not (rule in self.rrsets and wildcard in self.rrsets):
                try:
                    _, next_rule = rule.split('.', 1)
                except ValueError:
                    next_rule = None

                # If the current rule is a wildcard, then it already has an RRset configured. This
                # is because wildcard names cannot show up suddenly while moving up in the tree. We
                # therefore don't need to create it. It also does not need another child wildcard.
                if rule[0] != '*':
                    # If we have reached a domain without an explicit rule (empty non-terminal), we
                    # link it one level up. If it is a top-level domain, we link to the root.
                    if rule not in self.rrsets:
                        target = '*' if next_rule is None else next_rule
                        self._update_rrsets(rule, [('CNAME', target)])

                    # Add child wildcard if it does not exist
                    if wildcard not in self.rrsets:
                        self._update_rrsets(wildcard, [('CNAME', rule)])

                rule = next_rule
                wildcard = '*.{}'.format(rule)

    def _prioritize_wildcard_exception_rules(self):
        # Make sure exceptions always have priority (more specific rules don't win).
        # 
        # This is done by removing [???].<exception> entries. The case [???].*.<parent(exception)>
        # is covered by inline wildcard treatment above.
        # Then, point all subnames of a whilecard exception to the exception itself
        for rule in self.wildcard_exception_rules:
            self.rrsets = {subname: rrset
                           for subname, rrset in self.rrsets.items()
                           if not subname.endswith('.{}'.format(rule))}

    def _process(self):
        # This algorithm transforms Public Suffix List input into RRsets so that the public
        # suffix of a domain is given by the PTR record of <domain>.<SERVICE>. The pertinent
        # matching algorithm is described here: https://publicsuffix.org/list/

        # Add regular rules
        self._process_regular_rules()

        # May be overwriting wildcard CNAME from regular rules, so has to go after regular ones
        self._process_regular_wildcard_rules()

        # Find the next wildcard in the hierarchy and point to the rule covering its parent.
        self._process_wildcard_exception_rules()

        # The procedure may overwrite other wildcard rules, so it is run after them.
        self._process_inline_wildcard_rules()

        # Remove rules that do not apply any longer
        self._prioritize_wildcard_exception_rules()

        # Needs to run before the wildcard shadowing step because it relies on this one.
        self._add_root_rule()

        # Once the general structure is clear, fix up some stuff
        self._fix_wildcard_shadowing()

        # Add timestamp and checksum information
        timestamp = int(time.time())
        hexdigest = self.get_checksum()
        self._update_rrsets('', [('TXT', ['"{} {}"'.format(timestamp, hexdigest)])])

    def _process_inline_wildcard_rules(self):
        # Take care of inline wildcard and cut off the corresponding subtree (not supported)
        # To expose that the situation is not supported, do not set a PTR record. Instead,
        # set TXT records explicitly listing the rules that are not supported.

        # Let's collect the rules pertaining to each subtree, and then create the TXT record.
        inline_wildcard_mapping = defaultdict(list)
        for rule in self.inline_wildcard_rules:
            # Collect parents from the right-most wildcard and store the respective rule
            _, parent = rule.rsplit('*', 1)
            inline_wildcard_mapping[parent].append(rule)

        # Finalize rules and set TXT record
        for parent, rules in inline_wildcard_mapping.items():
            # The necessity to handle <...>.*.<parent> requires either setting up TXT records
            # with such names (which is not possible in DNS), or handling the situation at the
            # parent level, cutting off the tree there.
            # If a rule is present at that name (with only one wildcard at the very left), it
            # would erroneously also apply to all subnames, so it has to be rendered invalid.
            wildcard = '*{}'.format(parent)
            if wildcard in self.rrsets:
                rules.append(self.rrsets[wildcard][0]['records'][0][:-1])
            rules = ['"{}"'.format(rule) for rule in rules]

            # Set TXT RRset with applicable rules (replaces PTR)
            self._update_rrsets(wildcard, [('TXT', rules)])

    def _process_regular_rules(self):
        for suffix in self.regular_rules:
            self._update_rrsets(suffix, [('PTR', suffix)])

    def _process_regular_wildcard_rules(self):
        for wildcard_rule in self.proper_wildcard_rules:
            self._update_rrsets(wildcard_rule, [('PTR', wildcard_rule)])

    def _process_wildcard_exception_rules(self):
        for rule in self.wildcard_exception_rules:
            # Identify the parent of the next wildcard
            parent = rule
            while parent == rule or '*.{}'.format(parent) not in self.rrsets:
                try:
                    _, parent = parent.split('.', 1)
                except ValueError:
                    parent = '*'
                    break

            # This is the wildcard rule from which we are exempted
            wildcard = '*.{}'.format(parent)

            # From here, find the next covering rule. We try both <parent> and
            # <wildcard>.<parent's parent>, and then iterate.
            while parent != '*' and parent not in self.rrsets:
                try:
                    _, parent = parent.split('.', 1)
                except ValueError:
                    parent = '*'
                    break
                if '*.{}'.format(parent) in self.rrsets:
                    parent = '*.{}'.format(parent)

            # Create pointer to parent and document other relevant rules via TXT
            rules = [wildcard, '!{}'.format(rule)]
            self._update_rrsets(rule, [('PTR', parent),
                                       ('TXT', ['"{}"'.format(x) for x in rules])])

    def _update_rrsets(self, subname, contents):
        raise NotImplementedError

    def get_rrsets(self):
        raise NotImplementedError

    def process_line(self, line, update_hash=True):
        if update_hash:
            self.update_hash(line)

        rule = self.get_rule_from_line(line)
        if rule is None:
            return

        if rule.find('*', 1) > 0:
            self.logger.info('Rule not suitable for DNS: {}'.format(rule))
            self.inline_wildcard_rules.append(rule.encode('idna').decode('ascii'))
        elif rule[0] == '*':
            self.proper_wildcard_rules.append(rule.encode('idna').decode('ascii'))
        elif rule[0] == '!':
            self.wildcard_exception_rules.append(rule[1:].encode('idna').decode('ascii'))
        else:
            self.regular_rules.append(rule.encode('idna').decode('ascii'))

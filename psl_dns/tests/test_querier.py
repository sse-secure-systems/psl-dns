from unittest import mock, TestCase

import dns

import psl_dns


class TestBase(TestCase):
    def setUp(self):
        mock_resolver_class = mock.patch('dns.resolver.Resolver', autospec=True).start()
        self.mock_resolver = mock_resolver_class.return_value
        self.mock_resolver.query.return_value = [mock.create_autospec(dns.rdata.Rdata).return_value]
        self.addCleanup(mock.patch.stopall)

        self.psl = psl_dns.PSL()

    def get_mock_context_manager(self, value):
        if hasattr(value, '__call__'):
            return mock.patch.object(self.mock_resolver, 'query', side_effect=value)

        def _query_side_effect(_domain, rdatatype, **_):
            if isinstance(value, dict):
                records = value[rdatatype]
            else:
                records = value if isinstance(value, list) else [value]

            answers = []
            for record in records:
                answers.append(mock.create_autospec(dns.rdata.Rdata).return_value)
                answers[-1].to_text.return_value = record
            return answers

        return mock.patch.object(self.mock_resolver, 'query', side_effect=_query_side_effect)


class TestMisc(TestBase):
    def test_get_checksum(self):
        checksum = 'd205f587d61c6bbf05bec818776da1dd030ce68f2e8912fea732158b9a33cc54'
        with self.get_mock_context_manager('"1556058819 {}"'.format(checksum)):
            self.assertEqual(self.psl.get_checksum(), checksum)

    def test_nxdomain(self):
        with self.get_mock_context_manager(dns.resolver.NXDOMAIN):
            with self.assertRaises(psl_dns.exceptions.ResolverError):
                self.psl.query('iana.org', dns.rdatatype.PTR)

    def test_get_rules(self):
        mock_records = {dns.rdatatype.PTR: ['*.'], dns.rdatatype.TXT: ['"*.ck"', '"!www.ck"']}
        with self.get_mock_context_manager(mock_records):
            self.assertEqual(self.psl.get_rules('www.ck.'), {'!www.ck', '*.ck', '*'})
            self.mock_resolver.query.assert_called()


class TestGetPublicSuffix(TestBase):
    def assertGetPublicSuffix(self, domain, suffix):
        mock_answer = (suffix.rstrip('.') + '.').encode('idna').decode('ascii')
        with self.get_mock_context_manager(mock_answer):
            self.assertEqual(self.psl.get_public_suffix(domain), suffix)
            self.mock_resolver.query.assert_called()

    def test_ascii(self):
        self.assertGetPublicSuffix('io', 'io')
        self.assertGetPublicSuffix('dedyn.io', 'dedyn.io')
        self.assertGetPublicSuffix('desec.io', 'io')
        self.assertGetPublicSuffix('desec.io.', 'io.')

        # Also test lettercase normalization
        self.assertGetPublicSuffix('IO', 'io')
        self.assertGetPublicSuffix('s3.AmazonAWS.com', 's3.amazonaws.com')

    def test_punycode(self):
        self.assertGetPublicSuffix('www.xn--tsting-wxa.de.co.uk', 'co.uk')

    def test_unicode(self):
        self.assertGetPublicSuffix('www.tösting.co.uk', 'co.uk')
        self.assertGetPublicSuffix('www.xn--55qx5d.cn.', 'xn--55qx5d.cn.')
        self.assertGetPublicSuffix('www.公司.cn.', '公司.cn.')
        self.assertGetPublicSuffix('公司.cn', '公司.cn')

    def test_unsupported_rule_exception(self):
        with self.get_mock_context_manager(psl_dns.exceptions.UnsupportedRule):
            with self.assertRaises(psl_dns.exceptions.UnsupportedRule):
                self.psl.get_public_suffix('unsupported.wildcard.test')

    def test_invalid_domain(self):
        with self.assertRaises(ValueError):
            self.psl.get_public_suffix('.')

        with self.assertRaises(ValueError):
            self.psl.get_public_suffix('.desec.io')

    def test_inconsistent_labels(self):
        with self.get_mock_context_manager('dedyn.io.'):
            with self.assertRaises(ValueError):
                self.psl.get_public_suffix('www.desec.io')


class TestIsPublicSuffix(TestBase):
    def assertIsPublicSuffix(self, domain, suffix, value):
        mock_answer = (suffix.rstrip('.') + '.').encode('idna').decode('ascii')
        with self.get_mock_context_manager(mock_answer):
            self.assertEqual(self.psl.is_public_suffix(domain), value)
            self.mock_resolver.query.assert_called()

    def test_ascii(self):
        self.assertIsPublicSuffix('io', 'io', True)
        self.assertIsPublicSuffix('dedyn.io', 'dedyn.io', True)
        self.assertIsPublicSuffix('desec.io', 'io', False)
        self.assertIsPublicSuffix('desec.io.', 'io', False)

    def test_punycode(self):
        self.assertIsPublicSuffix('www.xn--tsting-wxa.de.co.uk', 'co.uk', False)

    def test_unicode(self):
        self.assertIsPublicSuffix('www.tösting.co.uk', 'co.uk', False)
        self.assertIsPublicSuffix('www.公司.cn.', '公司.cn', False)
        self.assertIsPublicSuffix('公司.cn', '公司.cn', True)

    def test_given_suffix(self):
        self.assertTrue(self.psl.is_public_suffix('something.ck', 'something.ck'))
        self.assertFalse(self.psl.is_public_suffix('something.ck', 'something.ck.'))

"""Offline wire-format checks for the static-tag report endpoint correction."""

import base64
import importlib.util
from pathlib import Path
import unittest


MODULE = Path(__file__).resolve().parents[1] / 'machoadi/fetch_reports.py'
SPEC = importlib.util.spec_from_file_location('static_fetch_reports', MODULE)
fetch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fetch)


class StaticReportProtocolTests(unittest.TestCase):
    def test_formal_static_client_defaults_to_verified_endpoint(self):
        self.assertEqual(fetch.URL, 'https://gateway.icloud.com/acsnservice/fetch')

    def test_legacy_and_v2_preserve_the_same_encrypted_payload(self):
        identifier = base64.b64encode(b'own synthetic identifier').decode()
        payload = base64.b64encode(b'synthetic encrypted report').decode()
        legacy = {'statusCode': '200', 'results': [{'id': identifier, 'payload': payload}]}
        v2 = {'acsnLocations': {'statusCode': '200', 'locationPayload': [
            {'id': identifier, 'locationInfo': [payload]}]}}
        self.assertEqual(fetch.parse_payload(legacy), fetch.parse_payload(v2))
        self.assertEqual(fetch.parse_payload(legacy)[1],
                         [(b'own synthetic identifier', b'synthetic encrypted report')])

    def test_empty_result_is_distinct_from_service_refusal(self):
        self.assertEqual(fetch.parse_payload({'statusCode': 200, 'results': []}), ('200', []))
        self.assertEqual(fetch.parse_payload({'statusCode': 500, 'results': []}), ('500', []))


if __name__ == '__main__':
    unittest.main()

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from lab.engine import ROOT, detect, load_events, load_rules


class DetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = load_rules()
        cls.cases = json.loads((ROOT / 'data/scenarios.json').read_text())

    def test_all_named_scenarios(self):
        for case in self.cases:
            with self.subTest(case=case['name']):
                actual = detect(case['events'], self.rules)
                self.assertEqual([a['rule_id'] for a in actual], case['expected_rule_ids'])

    def test_every_rule_has_positive_and_negative_scenarios(self):
        for rule in self.rules:
            named = [c for c in self.cases if c['name'].startswith(rule['id'])]
            self.assertTrue(any(rule['id'] in c['expected_rule_ids'] for c in named))
            self.assertTrue(any(not c['expected_rule_ids'] for c in named))

    def test_demo_matches_committed_golden_output(self):
        expected = json.loads((ROOT / 'examples/expected-alerts.json').read_text())
        actual = detect(load_events(ROOT / 'data/demo.jsonl'), self.rules)
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 5)

    def test_unsorted_input_is_equivalent(self):
        events = load_events(ROOT / 'data/demo.jsonl')
        self.assertEqual(detect(events, self.rules), detect(list(reversed(events)), self.rules))

    def test_timezone_offsets_are_compared_as_instants(self):
        events = copy.deepcopy(self.cases[0]['events'])
        events[-1]['timestamp'] = '2026-01-01T01:04:00+01:00'
        self.assertEqual([a['rule_id'] for a in detect(events, self.rules)], ['DE001'])

    def test_wrong_channel_and_provider_cannot_match_any_rule(self):
        for field in ('channel', 'provider'):
            events = load_events(ROOT / 'data/demo.jsonl')
            for event in events:
                event[field] = 'unrelated'
            self.assertEqual(detect(events, self.rules), [])

    def test_evidence_contains_exact_threshold_events(self):
        events = self.cases[0]['events']
        alert = detect(events, self.rules)[0]
        self.assertEqual([e['record_id'] for e in alert['evidence']], [e['record_id'] for e in events])

    def test_input_validation(self):
        good = load_events(ROOT / 'data/demo.jsonl')[0]
        bad = []
        for field, value in [('timestamp', '2026-01-01T00:00:00'), ('timestamp', 'bad'), ('event_id', True), ('host', ''), ('record_id', 1)]:
            event = {**good, field: value}
            bad.append(json.dumps(event))
        bad.extend(['{bad', '[]', 'null', json.dumps(good) + '\n' + json.dumps(good)])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'input.jsonl'
            for payload in bad:
                with self.subTest(payload=payload):
                    path.write_text(payload, encoding='utf-8')
                    with self.assertRaises(ValueError):
                        load_events(path)

    def test_same_record_id_on_different_hosts_is_valid(self):
        event = load_events(ROOT / 'data/demo.jsonl')[0]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'input.jsonl'
            path.write_text(json.dumps(event) + '\n' + json.dumps({**event, 'host': 'LAB-WS02'}))
            self.assertEqual(len(load_events(path)), 2)

    def test_cli_json_output_and_error_exit(self):
        ok = subprocess.run([sys.executable, '-m', 'lab.engine', 'data/demo.jsonl'], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual(len(json.loads(ok.stdout)), 5)
        error = subprocess.run([sys.executable, '-m', 'lab.engine', 'data/does-not-exist.jsonl'], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(error.returncode, 2)
        self.assertIn('error:', error.stderr)


if __name__ == '__main__':
    unittest.main()

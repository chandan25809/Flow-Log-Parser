import unittest
import os
from pathlib import Path
from flow_log_parser import FlowLogParser

TEST_DIR = Path("test_files")

class TestFlowLogLookup(unittest.TestCase):
    # Test parsing an empty lookup table
    def test_empty_lookup(self):
        path = TEST_DIR / "empty.txt"
        parser = FlowLogParser(None, path, None)
        parser.load_lookup_table()
        self.assertEqual(parser.lookup_table, {})

    # Test parsing a lookup table with invalid rows
    def test_invalid_lookup(self):
        path = TEST_DIR / "invalid_lookup_table.csv"
        parser = FlowLogParser(None, path, None)
        parser.load_lookup_table()
        expected_lookup = {
            ("25", "tcp"): "sv_P1",
            ("23", "tcp"): "sv_P1",
            ("443", "tcp"): "sv_P2",
            ("110", "tcp"): "email",
            ("993", "tcp"): "email",
            ("143", "tcp"): "email"
        }
        self.assertEqual(parser.lookup_table, expected_lookup)

    # Test parsing a valid lookup table
    def test_valid_lookup(self):
        path = TEST_DIR / "lookup_table.csv"
        parser = FlowLogParser(None, path, None)
        parser.load_lookup_table()
        expected_lookup = {
            ("25", "tcp"): "sv_P1",
            ("68", "udp"): "sv_P2",
            ("23", "tcp"): "sv_P1",
            ("31", "udp"): "SV_P3",
            ("443", "tcp"): "sv_P2",
            ("22", "tcp"): "sv_P4",
            ("3389", "tcp"): "sv_P5",
            ("0", "icmp"): "sv_P5",
            ("110", "tcp"): "email",
            ("993", "tcp"): "email",
            ("143", "tcp"): "email"
        }
        self.assertEqual(parser.lookup_table, expected_lookup)


class TestFlowLogProtocolMappings(unittest.TestCase):
    def setUp(self):
        self.mappings = FlowLogParser.gen_protocol_mappings(self)

    def test_udp_mapping(self):
        self.assertTrue("17" in self.mappings)
        self.assertEqual(self.mappings["17"], "udp")

    def test_tcp_mapping(self):
        self.assertTrue("6" in self.mappings)
        self.assertEqual(self.mappings["6"], "tcp")

    def test_icmp_mapping(self):
        self.assertTrue("1" in self.mappings)
        self.assertEqual(self.mappings["1"], "icmp")


class TestFlowLogProcessing(unittest.TestCase):
    # Set up a parser with a valid lookup table
    def setUp(self):
        lookup_path = TEST_DIR / "lookup_table.csv"
        self.parser = FlowLogParser(None, lookup_path, None)
        self.parser.load_lookup_table()

    # Test processing an empty log file
    def test_process_empty_log_file(self):
        log_path = TEST_DIR / "empty.txt"
        self.parser.log_file = log_path
        self.parser.process_logs()
        self.assertEqual(len(self.parser.tag_counts), 0)
        self.assertEqual(len(self.parser.port_protocol_counts), 0)

    # Test handling of invalid log entries
    def test_process_invalid_log_entries(self):
        log_path = TEST_DIR / "invalid_flow_logs.txt"
        self.parser.log_file = log_path
        self.parser.process_logs()
        expected_tags_counts = {"Untagged": 2}
        expected_protocol_counts = {("49153", "tcp"): 1, ("49154", "tcp"): 1}
        self.assertDictEqual(self.parser.port_protocol_counts, expected_protocol_counts)
        self.assertDictEqual(self.parser.tag_counts, expected_tags_counts)

    # Test processing valid log entries
    def test_process_valid_log_entries(self):
        log_path = TEST_DIR / "valid_flow_logs.txt"
        self.parser.log_file = log_path
        self.parser.process_logs()
        
        expected_tags_counts = {
            "sv_P2": 1,
            "Untagged": 2
        }
        
        expected_protocol_counts = {("443", "tcp"): 1, ("49154", "tcp"): 1, ("49155", "tcp"): 1}
        self.assertDictEqual(self.parser.port_protocol_counts, expected_protocol_counts)
        self.assertDictEqual(self.parser.tag_counts, expected_tags_counts)

    # Test handling of duplicate logs
    def test_process_duplicate_logs(self):
        log_path = TEST_DIR / "duplicate_logs.txt"
        self.parser.log_file = log_path
        self.parser.process_logs()
        expected_protocol_counts = {("49153", "tcp"): 2, ("49154", "tcp"): 1}
        expected_tags_counts = {"Untagged": 3}
        self.assertDictEqual(self.parser.port_protocol_counts, expected_protocol_counts)
        self.assertDictEqual(self.parser.tag_counts, expected_tags_counts)

    # Test if output file is created successfully
    def test_output_file_creation(self):
        log_path = TEST_DIR / "valid_flow_logs.txt"
        output_path = TEST_DIR / "test_output.txt"
        self.parser.log_file = log_path
        self.parser.output_file = output_path
        self.parser.process_logs()
        self.parser.write_output()
        self.assertTrue(output_path.exists())


if __name__ == "__main__":
    unittest.main()

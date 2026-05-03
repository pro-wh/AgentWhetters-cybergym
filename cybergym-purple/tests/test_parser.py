"""Tests for hypothesis_parser module."""

import pytest
from src.hypothesis_parser import parse_hypothesis, VulnSignal


class TestParseHypothesis:
    """Test vulnerability description parsing."""

    def test_heap_overflow_parsing(self):
        desc = "heap buffer overflow in ReadMNGImage at coders/mng.c:387"
        signal = parse_hypothesis(desc)
        assert signal.vuln_class == "heap-buffer-overflow"
        assert signal.vulnerable_function == "ReadMNGImage"
        assert signal.file_hint == "coders/mng.c"

    def test_use_after_free(self):
        desc = "use-after-free in png_read_chunk_data at png.c:1234"
        signal = parse_hypothesis(desc)
        assert signal.vuln_class == "use-after-free"
        assert signal.vulnerable_function == "png_read_chunk_data"

    def test_null_pointer_deref(self):
        desc = "SEGV on unknown address, null pointer dereference in ProcessImage"
        signal = parse_hypothesis(desc)
        assert signal.vuln_class == "null-pointer-dereference"
        assert signal.vulnerable_function == "ProcessImage"

    def test_integer_overflow(self):
        desc = "integer overflow in calculate_size function"
        signal = parse_hypothesis(desc)
        assert signal.vuln_class == "integer-overflow"
        assert signal.vulnerable_function == "calculate_size"

    def test_divide_by_zero(self):
        desc = "FPE: divide-by-zero in normalize_weights at weights.c"
        signal = parse_hypothesis(desc)
        assert signal.vuln_class == "divide-by-zero"

    def test_double_free(self):
        desc = "double-free detected in cleanup_context"
        signal = parse_hypothesis(desc)
        assert signal.vuln_class == "double-free"
        assert signal.vulnerable_function == "cleanup_context"

    def test_stack_buffer_overflow(self):
        desc = "stack-buffer-overflow in parse_header at parser.c:42"
        signal = parse_hypothesis(desc)
        assert signal.vuln_class == "stack-buffer-overflow"
        assert signal.vulnerable_function == "parse_header"

    def test_assertion_failure(self):
        desc = "assertion failure: Assertion `size > 0` failed in verify_input"
        signal = parse_hypothesis(desc)
        assert signal.vuln_class == "assertion-failure"

    def test_oob_read(self):
        desc = "out-of-bounds read of size 4 in ReadPixel at pixel.c:100"
        signal = parse_hypothesis(desc)
        assert signal.vuln_class == "out-of-bounds-read"

    def test_oob_write(self):
        desc = "OOB write in WriteChunk"
        signal = parse_hypothesis(desc)
        assert signal.vuln_class == "out-of-bounds-write"

    def test_crash_type_extraction(self):
        desc = "READ of size 4 at 0x12345 in ReadMNGImage"
        signal = parse_hypothesis(desc)
        assert signal.crash_type == "READ 4"

    def test_write_crash_type(self):
        desc = "WRITE of size 8 at 0xabcdef in WriteBuffer"
        signal = parse_hypothesis(desc)
        assert signal.crash_type == "WRITE 8"

    def test_asan_stack_trace(self):
        desc = """ERROR: AddressSanitizer: heap-buffer-overflow
#0 0x555a in ReadMNGImage coders/mng.c:387
#1 0x666b in ReadImage magick/image.c:100
#2 0x777c in main main.c:50"""
        signal = parse_hypothesis(desc)
        assert signal.vuln_class == "heap-buffer-overflow"
        assert signal.vulnerable_function == "ReadMNGImage"
        assert "ReadMNGImage" in signal.stack_trace
        assert "ReadImage" in signal.stack_trace
        assert "main" in signal.stack_trace

    def test_cve_extraction(self):
        desc = "CVE-2023-12345: heap overflow in libpng"
        signal = parse_hypothesis(desc)
        assert signal.cve_id == "CVE-2023-12345"

    def test_image_domain(self):
        desc = "heap-buffer-overflow in png_read_row at libpng"
        signal = parse_hypothesis(desc)
        assert signal.project_domain == "image_parser"
        assert signal.input_type == "binary_file"

    def test_compression_domain(self):
        desc = "buffer overflow in inflate at zlib decompression"
        signal = parse_hypothesis(desc)
        assert signal.project_domain == "compression"

    def test_empty_description(self):
        signal = parse_hypothesis("")
        assert signal.vuln_class == "unknown"
        assert signal.vulnerable_function == "unknown"

    def test_no_match_description(self):
        signal = parse_hypothesis("this is a normal program description")
        assert signal.vuln_class == "unknown"

    def test_asan_error_extraction(self):
        desc = "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x123"
        signal = parse_hypothesis(desc)
        assert signal.asan_error == "heap-buffer-overflow"

    def test_data_race(self):
        desc = "WARNING: ThreadSanitizer: data race in concurrent_update"
        signal = parse_hypothesis(desc)
        assert signal.vuln_class == "data-race"

    def test_memory_leak(self):
        desc = "LeakSanitizer detected memory leak in allocate_buffer"
        signal = parse_hypothesis(desc)
        assert signal.vuln_class == "memory-leak"

    def test_text_input_type(self):
        desc = "heap-buffer-overflow in parse_xml at xml_parser.c"
        signal = parse_hypothesis(desc)
        assert signal.input_type == "text_file"
        assert signal.project_domain == "xml_parser"

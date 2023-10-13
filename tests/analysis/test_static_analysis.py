from django.conf import settings
from django.test import TestCase

from analysis.analysis.static import *


class StaticAnalysisTestCase(TestCase):
    databases = ["elfen"]

    @classmethod
    def setUpTestData(cls):
        cls.tests_dir = os.path.join(settings.BASE_DIR, "tests", "analysis", "files")
        cls.bin_dir = os.path.join(cls.tests_dir, "binaries")

    def test_anti_analysis_check(self):
        """
        Check if the anomalies and anomalies-correcting backends are working as
        expected.
        """
        sha256 = "1eac86dd4dde2fdc06cb7b8d9dbe2573eff4cc7bc428f1a1c0aed65a80fad428"
        sample = SampleMetadata.objects.create(
            md5="7ded82f7147c1251ab55a70a1a3fd829",
            sha1="d40b901a2d3ea6c8cd033f4432878dca051685a2",
            sha256=sha256,
            username="test"
        )

        aa, aaa = detect_anti_analysis_techniques(sample, os.path.join(self.bin_dir, sha256))
        self.assertIsNotNone(aa.readelf, "Error - readelf didn't throw warnings")
        self.assertIsNotNone(aa.pyelftools, "Error - pyelftools didn't throw warnings")
        self.assertTrue(aaa.elflepton, "Error - elflepton flag wasn't set")

    def test_embedded_elf(self):
        """
        Check if the embedded elf finding backend is working as expected.
        """
        sha256 = "1a0de3871be4932abd0ace0dd12cd90a7c1cd27747612174d03c9dfe287ad0da"
        embedded_elf = parse_elf.get_embedded_elf(os.path.join(self.bin_dir, sha256))
        self.assertIsNotNone(embedded_elf, "Error - No embedded ELF was found.")
        self.assertEqual(len(embedded_elf), 1)
        self.assertEqual(embedded_elf[0][1], 15960)

    def test_apply_capa(self):
        """
        Check if the CAPA backend is working as expected.
        """
        # RC4 program copied from https://hideandsec.sh/books/red-teaming/page/the-rc4-encryption
        sha256 = "94d442a6511f8430e16f3bad31d3e3e81cfed72fe32450a294c8606963fd47d1"
        sample = SampleMetadata.objects.create(
            md5="6cd279f9f3a229e6f32c7aaf9c95e979",
            sha1="ef3a2ff38bfa249b219b19ee54b8370a8bfb9822",
            sha256=sha256,
            username="test"
        )
        expected_capa = {
            "base_address": 33554432,
            "rules": ["encrypt data using RC4 PRGA"],
            "namespaces": ["data-manipulation/encryption/rc4"],
            "addresses": [[33559680]]
        }

        capa = apply_capa(sample, os.path.join(self.bin_dir, sha256))
        for prop in expected_capa:
            self.assertEqual(expected_capa[prop], getattr(capa, prop))

    def test_apply_feature_extractor_truncated(self):
        """
        Check if sample feature extractor backend throws errors as expected
        for a severely truncated sample.
        """
        sha256 = "a7df93896cced4e217d696b6b0bbfb259ded4e80d05652c31646e7b4b86827ab"
        sample = SampleMetadata.objects.create(
            md5="10c624d1db546b2343e531f7134ab8c8",
            sha1="bacef808865c0a4f4bb3c59fffcac239fd3b517f",
            sha256=sha256,
            username="test"
        )

        try:
            apply_feature_extractor(sample, os.path.join(self.bin_dir, sha256))
            self.fail("No error raised for truncated sample. This is unexpected.")
        except AttributeError:
            pass

    def test_apply_feature_extractor(self):
        """
        Check if sample feature extractor backend is working as expected for non-stripped sample
        """
        sha256 = "374e76244ff579278f294a3b70bed0b27c7d089d101d9eb97af26a04c33a5bd2"
        sample = SampleMetadata.objects.create(
            md5="a21ab06cd66dc42965fbe807317d76a8",
            sha1="4f8a3328d3b2bd38817039cf92379dcb0b34aca7",
            sha256=sha256,
            username="test"
        )
        expected_features = {
            "average_entropy": 4.25699610467002,
            "highest_block_entropy": 5.0169470669279335,
            "entry_point_bytes": b"\xd8\x02\x00\x00\x00\x00\x00\x00\xd8\x02\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00",
            "packed": "unknown",
            "truncated": False,
            "stripped": False,
            "interp": "/lib64/ld-linux-x86-64.so.2",
            "num_segments": 13,
            "num_sections": 31,
            "num_symtab_symbols": 36,
            "num_dynsym_symbols": 7,
            "filesize": 15960,
            "lib_deps": ["libc.so.6"],
            "os": "linux",
            "arch": "amd64",
            "endian": "LE",
            "bit": "bits_64",
            "compiler": "GCC 11.4.0",
            "imports": [
                "__libc_start_main", "_ITM_deregisterTMCloneTable", "puts", "__gmon_start__",
                "_ITM_registerTMCloneTable", "__cxa_finalize"
            ],
            "exports": []
        }

        features = apply_feature_extractor(sample, os.path.join(self.bin_dir, sha256))
        for prop in expected_features:
            self.assertEqual(expected_features[prop], getattr(features, prop))

    def test_parse_elf_section_header(self):
        """
        Check if ELF section header is parsed as expected for a non-stripped binary.
        """
        sha256 = "374e76244ff579278f294a3b70bed0b27c7d089d101d9eb97af26a04c33a5bd2"
        sample = SampleMetadata.objects.create(
            md5="a21ab06cd66dc42965fbe807317d76a8",
            sha1="4f8a3328d3b2bd38817039cf92379dcb0b34aca7",
            sha256=sha256,
            username="test"
        )
        expected_elfsectionheader = {
            "sh_name": [
                0, 27, 35, 54, 73, 87, 97, 105, 113, 126, 141, 151, 161, 156,
                167, 176, 185, 191, 197, 205, 219, 229, 241, 253, 171, 262,
                268, 273, 1, 9, 17
            ],
            "sh_name_str": [
                b"", b"\x2e\x69\x6e\x74\x65\x72\x70",
                b"\x2e\x6e\x6f\x74\x65\x2e\x67\x6e\x75\x2e\x70\x72\x6f\x70\x65\x72\x74\x79",
                b"\x2e\x6e\x6f\x74\x65\x2e\x67\x6e\x75\x2e\x62\x75\x69\x6c\x64\x2d\x69\x64",
                b"\x2e\x6e\x6f\x74\x65\x2e\x41\x42\x49\x2d\x74\x61\x67",
                b"\x2e\x67\x6e\x75\x2e\x68\x61\x73\x68", b"\x2e\x64\x79\x6e\x73\x79\x6d",
                b"\x2e\x64\x79\x6e\x73\x74\x72", b"\x2e\x67\x6e\x75\x2e\x76\x65\x72\x73\x69\x6f\x6e",
                b"\x2e\x67\x6e\x75\x2e\x76\x65\x72\x73\x69\x6f\x6e\x5f\x72",
                b"\x2e\x72\x65\x6c\x61\x2e\x64\x79\x6e", b"\x2e\x72\x65\x6c\x61\x2e\x70\x6c\x74",
                b"\x2e\x69\x6e\x69\x74", b"\x2e\x70\x6c\x74", b"\x2e\x70\x6c\x74\x2e\x67\x6f\x74",
                b"\x2e\x70\x6c\x74\x2e\x73\x65\x63", b"\x2e\x74\x65\x78\x74", b"\x2e\x66\x69\x6e\x69",
                b"\x2e\x72\x6f\x64\x61\x74\x61", b"\x2e\x65\x68\x5f\x66\x72\x61\x6d\x65\x5f\x68\x64\x72",
                b"\x2e\x65\x68\x5f\x66\x72\x61\x6d\x65", b"\x2e\x69\x6e\x69\x74\x5f\x61\x72\x72\x61\x79",
                b"\x2e\x66\x69\x6e\x69\x5f\x61\x72\x72\x61\x79", b"\x2e\x64\x79\x6e\x61\x6d\x69\x63",
                b"\x2e\x67\x6f\x74", b"\x2e\x64\x61\x74\x61", b"\x2e\x62\x73\x73",
                b"\x2e\x63\x6f\x6d\x6d\x65\x6e\x74", b"\x2e\x73\x79\x6d\x74\x61\x62",
                b"\x2e\x73\x74\x72\x74\x61\x62", b"\x2e\x73\x68\x73\x74\x72\x74\x61\x62"
            ],
            "sh_type": [
                "SHT_NULL", "SHT_PROGBITS", "SHT_NOTE", "SHT_NOTE", "SHT_NOTE", "SHT_GNU_HASH",
                "SHT_DYNSYM", "SHT_STRTAB", "SHT_GNU_versym", "SHT_GNU_verneed", "SHT_RELA", "SHT_RELA",
                "SHT_PROGBITS", "SHT_PROGBITS", "SHT_PROGBITS", "SHT_PROGBITS", "SHT_PROGBITS",
                "SHT_PROGBITS", "SHT_PROGBITS", "SHT_PROGBITS", "SHT_PROGBITS", "SHT_INIT_ARRAY",
                "SHT_FINI_ARRAY", "SHT_DYNAMIC", "SHT_PROGBITS", "SHT_PROGBITS", "SHT_NOBITS",
                "SHT_PROGBITS", "SHT_SYMTAB", "SHT_STRTAB", "SHT_STRTAB"
            ],
            "sh_flags": [
                0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 66, 6, 6, 6, 6, 6, 6, 2, 2, 2, 3, 3, 3, 3, 3, 3,
                48, 0, 0, 0
            ],
            "sh_addr": [
                0, 792, 824, 872, 908, 944, 984, 1152, 1294, 1312, 1360, 1552, 4096, 4128, 4160,
                4176, 4192, 4456, 8192, 8208, 8264, 15800, 15808, 15816, 16312, 16384, 16400, 0,
                0, 0, 0
            ],
            "sh_offset": [
                0, 792, 824, 872, 908, 944, 984, 1152, 1294, 1312, 1360, 1552, 4096, 4128, 4160,
                4176, 4192, 4456, 8192, 8208, 8264, 11704, 11712, 11720, 12216, 12288, 12304,
                12304, 12352, 13216, 13691
            ],
            "sh_size": [
                0, 28, 48, 36, 32, 36, 168, 141, 14, 48, 192, 24, 27, 32, 16, 16, 263, 13,
                16, 52, 172, 8, 8, 496, 72, 16, 8, 43, 864, 475, 282
            ],
            "sh_link": [
                0, 0, 0, 0, 0, 6, 7, 0, 6, 7, 6, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0,
                0, 0, 29, 0, 0
            ],
            "sh_info": [
                0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 18, 0, 0
            ],
            "sh_addralign": [
                0, 1, 8, 4, 4, 8, 8, 1, 2, 8, 8, 8, 4, 16, 16, 16, 16, 4, 4, 4, 8, 8, 8, 8, 8,
                8, 1, 1, 8, 1, 1
            ],
            "sh_entsize": [
                0, 0, 0, 0, 0, 0, 24, 0, 2, 0, 24, 24, 0, 16, 16, 16, 0, 0 , 0 , 0, 0, 8, 8,
                16, 8, 0, 0, 1, 24, 0, 0
            ],
        }

        basic_info, _, _ = parse_elf.get_basic_info(os.path.join(self.bin_dir, sha256))
        elfsectionheader = parse_elf_section_header(sample, basic_info)
        for prop in expected_elfsectionheader:
            self.assertEqual(expected_elfsectionheader[prop], getattr(elfsectionheader, prop))

    def test_parse_elf_section_header_stripped(self):
        """
        Check if ELF section header is parsed as expected for a stripped binary.
        """
        sha256 = "44a19f785c695a90f7ace5d17feb25a7c7e95f9ce609117138c739276fc145ff"
        sample = SampleMetadata.objects.create(
            md5="973b31f527aee5e562d69b843520b94b",
            sha1="a9875e0c1066abe11c3e2471103e67ef935ef74a",
            sha256=sha256,
            username="test"
        )
        expected_elfsectionheader = {
            "sh_name": [
                0, 11, 19, 38, 57, 71, 81, 89, 97, 110, 125, 135, 145, 140, 151,
                160, 169, 175, 181, 189, 203, 213, 225, 237, 155, 246, 252, 257, 1
            ],
            "sh_name_str": [
                b"", b"\x2e\x69\x6e\x74\x65\x72\x70",
                b"\x2e\x6e\x6f\x74\x65\x2e\x67\x6e\x75\x2e\x70\x72\x6f\x70\x65\x72\x74\x79",
                b"\x2e\x6e\x6f\x74\x65\x2e\x67\x6e\x75\x2e\x62\x75\x69\x6c\x64\x2d\x69\x64",
                b"\x2e\x6e\x6f\x74\x65\x2e\x41\x42\x49\x2d\x74\x61\x67",
                b"\x2e\x67\x6e\x75\x2e\x68\x61\x73\x68", b"\x2e\x64\x79\x6e\x73\x79\x6d",
                b"\x2e\x64\x79\x6e\x73\x74\x72", b"\x2e\x67\x6e\x75\x2e\x76\x65\x72\x73\x69\x6f\x6e",
                b"\x2e\x67\x6e\x75\x2e\x76\x65\x72\x73\x69\x6f\x6e\x5f\x72",
                b"\x2e\x72\x65\x6c\x61\x2e\x64\x79\x6e", b"\x2e\x72\x65\x6c\x61\x2e\x70\x6c\x74",
                b"\x2e\x69\x6e\x69\x74", b"\x2e\x70\x6c\x74", b"\x2e\x70\x6c\x74\x2e\x67\x6f\x74",
                b"\x2e\x70\x6c\x74\x2e\x73\x65\x63", b"\x2e\x74\x65\x78\x74", b"\x2e\x66\x69\x6e\x69",
                b"\x2e\x72\x6f\x64\x61\x74\x61", b"\x2e\x65\x68\x5f\x66\x72\x61\x6d\x65\x5f\x68\x64\x72",
                b"\x2e\x65\x68\x5f\x66\x72\x61\x6d\x65", b"\x2e\x69\x6e\x69\x74\x5f\x61\x72\x72\x61\x79",
                b"\x2e\x66\x69\x6e\x69\x5f\x61\x72\x72\x61\x79", b"\x2e\x64\x79\x6e\x61\x6d\x69\x63",
                b"\x2e\x67\x6f\x74", b"\x2e\x64\x61\x74\x61", b"\x2e\x62\x73\x73",
                b"\x2e\x63\x6f\x6d\x6d\x65\x6e\x74", b"\x2e\x73\x68\x73\x74\x72\x74\x61\x62"
            ],
            "sh_type": [
                "SHT_NULL", "SHT_PROGBITS", "SHT_NOTE", "SHT_NOTE", "SHT_NOTE", "SHT_GNU_HASH",
                "SHT_DYNSYM", "SHT_STRTAB", "SHT_GNU_versym", "SHT_GNU_verneed", "SHT_RELA", "SHT_RELA",
                "SHT_PROGBITS", "SHT_PROGBITS", "SHT_PROGBITS", "SHT_PROGBITS", "SHT_PROGBITS",
                "SHT_PROGBITS", "SHT_PROGBITS", "SHT_PROGBITS", "SHT_PROGBITS", "SHT_INIT_ARRAY",
                "SHT_FINI_ARRAY", "SHT_DYNAMIC", "SHT_PROGBITS", "SHT_PROGBITS", "SHT_NOBITS",
                "SHT_PROGBITS", "SHT_STRTAB"
            ],
            "sh_flags": [
                0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 66, 6, 6, 6, 6, 6, 6, 2, 2, 2, 3, 3, 3, 3, 3, 3, 48
                , 0
            ],
            "sh_addr": [
                0, 792, 824, 872, 908, 944, 984, 1152, 1294, 1312, 1360, 1552, 4096, 4128, 4160, 4176,
                4192, 4456, 8192, 8208, 8264, 15800, 15808, 15816, 16312, 16384, 16400, 0, 0
            ],
            "sh_offset": [
                0, 792, 824, 872, 908, 944, 984, 1152, 1294, 1312, 1360, 1552, 4096, 4128, 4160, 4176,
                4192, 4456, 8192, 8208, 8264, 11704, 11712, 11720, 12216, 12288, 12304, 12304, 12347
            ],
            "sh_size": [
                0, 28, 48, 36, 32, 36, 168, 141, 14, 48, 192, 24, 27, 32, 16, 16, 263, 13, 16, 52, 172,
                8, 8, 496, 72, 16, 8, 43, 266
            ],
            "sh_link": [
                0, 0, 0, 0, 0, 6, 7, 0, 6, 7, 6, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0
            ],
            "sh_info": [
                0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ],
            "sh_addralign": [
                0, 1, 8, 4, 4, 8, 8, 1, 2, 8, 8, 8, 4, 16, 16, 16, 16, 4, 4, 4, 8, 8, 8, 8, 8, 8, 1,
                1, 1
            ],
            "sh_entsize": [
                0, 0, 0, 0, 0, 0, 24, 0, 2, 0, 24, 24, 0, 16, 16, 16, 0, 0, 0, 0, 0, 8, 8, 16, 8, 0,
                0, 1, 0
            ],
        }

        basic_info, _, _ = parse_elf.get_basic_info(os.path.join(self.bin_dir, sha256))
        elfsectionheader = parse_elf_section_header(sample, basic_info)
        for prop in expected_elfsectionheader:
            self.assertEqual(expected_elfsectionheader[prop], getattr(elfsectionheader, prop))

    def test_parse_elf_program_header(self):
        """
        Check if ELF program header is parsed as expected for a non-stripped binary.
        """
        sha256 = "374e76244ff579278f294a3b70bed0b27c7d089d101d9eb97af26a04c33a5bd2"
        sample = SampleMetadata.objects.create(
            md5="a21ab06cd66dc42965fbe807317d76a8",
            sha1="4f8a3328d3b2bd38817039cf92379dcb0b34aca7",
            sha256=sha256,
            username="test"
        )
        expected_elfprogheader = {
            "p_type": [
                "PT_PHDR", "PT_INTERP", "PT_LOAD", "PT_LOAD", "PT_LOAD", "PT_LOAD",
                "PT_DYNAMIC", "PT_NOTE", "PT_NOTE", "PT_GNU_PROPERTY", "PT_GNU_EH_FRAME",
                "PT_GNU_STACK", "PT_GNU_RELRO"
            ],
            "p_offset": [
                64, 792, 0, 4096, 8192, 11704, 11720, 824, 872, 824,
                8208, 0, 11704
            ],
            "p_flags": [4, 4, 4, 5, 4, 6, 6, 4, 4, 4, 4, 6, 4],
            "p_vaddr": [
                64, 792, 0, 4096, 8192, 15800, 15816, 824, 872, 824,
                8208, 0, 15800
            ],
            "p_paddr": [
                64, 792, 0, 4096, 8192, 15800, 15816, 824, 872,
                824, 8208, 0, 15800
            ],
            "p_filesz": [
                728, 28, 1576, 373, 244, 600, 496, 48, 68, 48, 52, 0, 584
            ],
            "p_memsz": [
                728, 28, 1576, 373, 244, 608, 496, 48, 68, 48, 52, 0, 584
            ],
            "p_align": [
                8, 1, 4096, 4096, 4096, 4096, 8, 8, 4, 8, 4, 16, 1
            ]
        }

        basic_info, _, _ = parse_elf.get_basic_info(os.path.join(self.bin_dir, sha256))
        elfprogheader = parse_elf_program_header(sample, basic_info)
        for prop in expected_elfprogheader:
            self.assertEqual(expected_elfprogheader[prop], getattr(elfprogheader, prop))

    def test_parse_elf_header(self):
        """
        Check if ELF header is parsed as expected for a non-stripped ELF binary.
        """
        sha256 = "374e76244ff579278f294a3b70bed0b27c7d089d101d9eb97af26a04c33a5bd2"
        expected_elfheader = {
            "e_ident_magic": b"\x7fELF",
            "e_ident_ei_class": "ELFCLASS64",
            "e_ident_ei_data": "ELFDATA2LSB",
            "e_ident_ei_version": "EV_CURRENT",
            "e_ident_ei_osabi": "ELFOSABI_SYSV",
            "e_ident_ei_abiversion": 0,
            "e_ident_ei_pad": b"\x00\x00\x00\x00\x00\x00\x00",
            "e_ident_ei_nident": 16,
            "e_type": "ET_DYN",
            "e_machine": "EM_X86_64",
            "e_version": "EV_CURRENT",
            "e_entry": 4192,
            "e_phoff": 64,
            "e_shoff": 13976,
            "e_flags": 0,
            "e_ehsize": 64,
            "e_phentsize": 56,
            "e_phnum": 13,
            "e_shentsize": 64,
            "e_shnum": 31,
            "e_shstrndx": 30,
        }
        sample = SampleMetadata.objects.create(
            md5="a21ab06cd66dc42965fbe807317d76a8",
            sha1="4f8a3328d3b2bd38817039cf92379dcb0b34aca7",
            sha256=sha256,
            username="test"
        )

        basic_info, _, _ = parse_elf.get_basic_info(os.path.join(self.bin_dir, sha256))
        elfheader = parse_elf_header(sample, basic_info)
        for prop in expected_elfheader:
            self.assertEqual(expected_elfheader[prop], getattr(elfheader, prop))

    def test_parse_elf_header_stripped(self):
        """
        Check if ELF header is parsed as expected for a stripped ELF binary.
        """
        sha256 = "44a19f785c695a90f7ace5d17feb25a7c7e95f9ce609117138c739276fc145ff"
        expected_elfheader = {
            "e_shoff": 12616,
            "e_shnum": 29,
            "e_shstrndx": 28,
        }
        sample = SampleMetadata.objects.create(
            md5="973b31f527aee5e562d69b843520b94b",
            sha1="a9875e0c1066abe11c3e2471103e67ef935ef74a",
            sha256=sha256,
            username="test"
        )

        basic_info, _, _ = parse_elf.get_basic_info(os.path.join(self.bin_dir, sha256))
        elfheader = parse_elf_header(sample, basic_info)
        for prop in expected_elfheader:
            self.assertEqual(expected_elfheader[prop], getattr(elfheader, prop))

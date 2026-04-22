from pathlib import Path
import csv
import pefile

BASE_DIR = Path(__file__).resolve().parent


from pathlib import Path
import csv
import pefile

BASE_DIR = Path(__file__).resolve().parent


class SavePeFeature:
    COLS = [
        'filename', 'e_magic', 'e_lfanew', 'e_minalloc', 'e_ovno', 'Signature', 'Machine', 'NumberOfSections',
        'TimeDateStamp', 'PointerToSymbolTable', 'NumberOfSymbols', 'SizeOfOptionalHeader', 'Characteristics',
        'Magic', 'SizeOfCode', 'AddressOfEntryPoint', 'BaseOfCode', 'ImageBase', "EntryPoint", "SectionAlignment",
        "FileAlignment", 'SizeOfImage', 'SizeOfHeaders', 'CheckSum', 'Subsystem', 'NumberOfRvaAndSizes',
        'CompareNumberOfSections', '.textSectionName', '.textSectionVirtualSize',
        '.textSection|VirtualSize-SizeOfRawData|', '.textSectionVirtualAddress', '.textSectionSizeOfRawData',
        '.textSectionPointerToRawData', '.textSectionCharacteristics', '.textSectionEntropy',
        '.dataSectionName', '.dataSectionVirtualSize', '.dataSection|VirtualSize-SizeOfRawData|',
        '.dataSectionVirtualAddress', '.dataSectionSizeOfRawData', '.dataSectionPointerToRawData',
        '.dataSectionCharacteristics', '.dataSectionEntropy', '.rsrcSectionName', '.rsrcSectionVirtualSize',
        '.rsrcSection|VirtualSize-SizeOfRawData|', '.rsrcSectionVirtualAddress', '.rsrcSectionSizeOfRawData',
        '.rsrcSectionPointerToRawData', '.rsrcSectionCharacteristics', '.rsrcSectionEntropy',
        '.rdataSectionName', '.rdataSectionVirtualSize', '.rdataSection|VirtualSize-SizeOfRawData|',
        '.rdataSectionVirtualAddress', '.rdataSectionSizeOfRawData', '.rdataSectionPointerToRawData',
        '.rdataSectionCharacteristics', '.rdataSectionEntropy', '.relocSectionName', '.relocSectionVirtualSize',
        '.relocSection|VirtualSize-SizeOfRawData|', '.relocSectionVirtualAddress', '.relocSectionSizeOfRawData',
        '.relocSectionPointerToRawData', '.relocSectionCharacteristics', '.relocSectionEntropy',
        'TotalNumberOfFunctionInIAT', 'TotalNumberOfFunctionInEAT',
        'rich_header_is_exist', 'raw_rich_header', 'MajorLinkerVersion', 'MinorLinkerVersion',
        'SizeOfInitializedData', 'SizeOfUninitializedData', 'SizeOfStackReserve', 'DllCharacteristics'
    ]

    SECTION_NAMES = [".text", ".data", ".rsrc", ".rdata", ".reloc"]

    def __init__(self, output_csv: Path, input_dir: Path):
        self.input_dir = Path(input_dir)
        self.output_csv = Path(output_csv)

        if not self.input_dir.exists():
            print(f"[!] Skip: folder not found -> {self.input_dir}")
            return

        if not self.input_dir.is_dir():
            print(f"[!] Skip: not a directory -> {self.input_dir}")
            return

        print(f"[+] Saving PE features from: {self.input_dir}")

        files = sorted([p for p in self.input_dir.iterdir() if p.is_file()])

        if not files:
            print(f"[!] Skip: no files in folder -> {self.input_dir}")
            return

        with self.output_csv.open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(self.COLS)

            for idx, file_path in enumerate(files, start=1):
                try:
                    pe = pefile.PE(str(file_path))
                    feature = self.extract_pe_features(pe, file_path.name)
                except Exception as e:
                    print(f"[{idx}] {file_path.name} -> parse failed ({e})")
                    feature = self.make_null_row(file_path.name)

                writer.writerow(feature)

        print(f"[-] Saved: {self.output_csv}")

    @classmethod
    def make_null_row(cls, filename: str):
        row = [None] * len(cls.COLS)
        row[0] = filename
        return row

    @staticmethod
    def normalize_section_name(raw_name: bytes) -> str:
        return raw_name.rstrip(b"\x00").decode(errors="ignore") if raw_name else ""

    @classmethod
    def get_section_features(cls, pe, target_name: str):
        for section in pe.sections:
            sec_name = cls.normalize_section_name(section.Name)
            if sec_name == target_name:
                return [
                    sec_name,
                    section.Misc_VirtualSize,
                    abs(section.Misc_VirtualSize - section.SizeOfRawData),
                    section.VirtualAddress,
                    section.SizeOfRawData,
                    section.PointerToRawData,
                    section.Characteristics,
                    section.get_entropy()
                ]
        return [None, None, None, None, None, None, None, None]

    @classmethod
    def extract_pe_features(cls, pe, filename: str):
        row = [filename]

        row.extend([
            pe.DOS_HEADER.e_magic,
            pe.DOS_HEADER.e_lfanew,
            pe.DOS_HEADER.e_minalloc,
            pe.DOS_HEADER.e_ovno
        ])

        row.append(pe.NT_HEADERS.Signature)

        row.extend([
            pe.FILE_HEADER.Machine,
            pe.FILE_HEADER.NumberOfSections,
            pe.FILE_HEADER.TimeDateStamp,
            pe.FILE_HEADER.PointerToSymbolTable,
            pe.FILE_HEADER.NumberOfSymbols,
            pe.FILE_HEADER.SizeOfOptionalHeader,
            pe.FILE_HEADER.Characteristics
        ])

        row.extend([
            pe.OPTIONAL_HEADER.Magic,
            pe.OPTIONAL_HEADER.SizeOfCode,
            pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            pe.OPTIONAL_HEADER.BaseOfCode,
            pe.OPTIONAL_HEADER.ImageBase,
            pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase,
            pe.OPTIONAL_HEADER.SectionAlignment,
            pe.OPTIONAL_HEADER.FileAlignment,
            pe.OPTIONAL_HEADER.SizeOfImage,
            pe.OPTIONAL_HEADER.SizeOfHeaders,
            pe.OPTIONAL_HEADER.CheckSum,
            pe.OPTIONAL_HEADER.Subsystem,
            pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        ])

        row.append(int(pe.FILE_HEADER.NumberOfSections == len(pe.sections)))

        for section_name in cls.SECTION_NAMES:
            row.extend(cls.get_section_features(pe, section_name))

        try:
            pe.parse_data_directories()
            total_iat_number = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
        except Exception:
            total_iat_number = 0
        row.append(total_iat_number)

        try:
            total_eat_number = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        except Exception:
            total_eat_number = 0
        row.append(total_eat_number)

        try:
            rich = pe.parse_rich_header()
            row.extend([1, str(rich.get("raw_data"))])
        except Exception:
            row.extend([0, None])

        for attr in [
            "MajorLinkerVersion",
            "MinorLinkerVersion",
            "SizeOfInitializedData",
            "SizeOfUninitializedData",
            "SizeOfStackReserve",
            "DllCharacteristics"
        ]:
            row.append(getattr(pe.OPTIONAL_HEADER, attr, None))

        return row


class MakingPeFeatures:
    def __init__(self):
        SavePeFeature(
            output_csv=BASE_DIR / "pe_features.csv",
            input_dir=BASE_DIR / "train_data"
        )

        SavePeFeature(
            output_csv=BASE_DIR / "validation_features.csv",
            input_dir=BASE_DIR / "validation_data"
        )

        SavePeFeature(
            output_csv=BASE_DIR / "test_features.csv",
            input_dir=BASE_DIR / "test_data"
        )


if __name__ == "__main__":
    MakingPeFeatures()
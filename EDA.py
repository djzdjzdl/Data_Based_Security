import pefile, os, csv
import shutil

class Save_Pe_Feature:

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
        #Added
        'exist_rich_header', 'raw_rich_header'
    ]

    #Train data based data analysis
    file_path = './train_data'
    NULL_ROW = [0 for x in COLS]

    def __init__(self):

        files = os.listdir(Save_Pe_Feature.file_path)
        with open('./pe_features.csv', 'w+', newline='') as csvs:
            wp = csv.writer(csvs)
            wp.writerow(Save_Pe_Feature.COLS)
            for idx, file in enumerate(files):
                try:
                    pe = pefile.PE(os.path.join(Save_Pe_Feature.file_path, file) )
                    feature = Save_Pe_Feature.Extract_Pe_Features(pe, file)
                except:
                    print('[+] {}'.format(file))
                    feature = Save_Pe_Feature.NULL_ROW
                    feature[0] = file
                wp.writerow(feature)
        Save_Pe_Feature.Save_Pe_Label()

    #Extract from PE Features 
    def Extract_Pe_Features(pe, filename):
        # add filename
        row = [filename]
        # add DOS_HEADER
        row.extend([pe.DOS_HEADER.e_magic, pe.DOS_HEADER.e_lfanew, pe.DOS_HEADER.e_minalloc, pe.DOS_HEADER.e_ovno])
        # add NT_HEADERS
        row.extend([pe.NT_HEADERS.Signature])
        # add FILE_HEADER
        row.extend([pe.FILE_HEADER.Machine, pe.FILE_HEADER.NumberOfSections, pe.FILE_HEADER.TimeDateStamp,
                    pe.FILE_HEADER.PointerToSymbolTable, pe.FILE_HEADER.NumberOfSymbols,
                    pe.FILE_HEADER.SizeOfOptionalHeader, pe.FILE_HEADER.Characteristics])
        # add OPTIONAL_HEADER
        row.extend([pe.OPTIONAL_HEADER.Magic, pe.OPTIONAL_HEADER.SizeOfCode,
                    pe.OPTIONAL_HEADER.AddressOfEntryPoint, pe.OPTIONAL_HEADER.BaseOfCode,
                    pe.OPTIONAL_HEADER.ImageBase,
                    pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase,
                    pe.OPTIONAL_HEADER.SectionAlignment, pe.OPTIONAL_HEADER.FileAlignment,
                    pe.OPTIONAL_HEADER.SizeOfImage, pe.OPTIONAL_HEADER.SizeOfHeaders,
                    pe.OPTIONAL_HEADER.CheckSum, pe.OPTIONAL_HEADER.Subsystem,
                    pe.OPTIONAL_HEADER.NumberOfRvaAndSizes])

        # add CompareNumberOfSections
        total_section_number = 0
        for section in pe.sections:
            total_section_number += 1
        if pe.FILE_HEADER.NumberOfSections == total_section_number:
            row.extend(["1"]) #1 is true
        else:
            row.extend(["0"]) #0 is false

        # add .text features
        text_number = 0
        for section in pe.sections:
            try:
                if section.Name == b".text\x00\x00\x00":
                    text_number += 1
                    row.extend([section.Name, section.Misc_VirtualSize,
                                abs(section.Misc_VirtualSize - section.SizeOfRawData),
                                section.VirtualAddress, section.SizeOfRawData, section.PointerToRawData,
                                section.Characteristics, section.get_entropy()])
                    break
            except AttributeError:
                row.extend(["Error", "Error", "Error", "Error", "Error", "Error", "Error", "Error"])
        if text_number == 0:
            row.extend(["None", "None", "None", "None", "None", "None", "None", "None"])

        # add .data features
        data_number = 0
        for section in pe.sections:
            try:
                if section.Name == b".data\x00\x00":
                    data_number += 1
                    row.extend([section.Name, section.Misc_VirtualSize,
                                abs(section.Misc_VirtualSize - section.SizeOfRawData),
                                section.VirtualAddress, section.SizeOfRawData, section.PointerToRawData,
                                section.Characteristics, section.get_entropy()])
                    break
            except AttributeError:
                row.extend(["Error", "Error", "Error", "Error", "Error", "Error", "Error", "Error"])
        if data_number == 0:
            row.extend(["None", "None", "None", "None", "None", "None", "None", "None"])

        # add .rsrc features
        rsrc_number = 0
        for section in pe.sections:
            try:
                if section.Name == b".rsrc\x00\x00\x00":
                    rsrc_number += 1
                    row.extend([section.Name, section.Misc_VirtualSize,
                                abs(section.Misc_VirtualSize - section.SizeOfRawData),
                                section.VirtualAddress, section.SizeOfRawData, section.PointerToRawData,
                                section.Characteristics, section.get_entropy()])
                    break
            except AttributeError:
                row.extend(["Error", "Error", "Error", "Error", "Error", "Error", "Error", "Error"])
        if rsrc_number == 0:
            row.extend(["None", "None", "None", "None", "None", "None", "None", "None"])

        # add .rdata features
        rdata_number = 0
        for section in pe.sections:
            try:
                if section.Name == b".rdata\x00\x00":
                    rdata_number += 1
                    row.extend([section.Name, section.Misc_VirtualSize,
                                abs(section.Misc_VirtualSize - section.SizeOfRawData),
                                section.VirtualAddress, section.SizeOfRawData, section.PointerToRawData,
                                section.Characteristics, section.get_entropy()])
                    break
            except AttributeError:
                row.extend(["Error", "Error", "Error", "Error", "Error", "Error", "Error", "Error"])
        if rdata_number == 0:
            row.extend(["None", "None", "None", "None", "None", "None", "None", "None"])

        # add .reloc features
        reloc_number = 0
        for section in pe.sections:
            try:
                if section.Name == b".reloc\x00\x00":
                    reloc_number += 1
                    row.extend([section.Name, section.Misc_VirtualSize,
                                abs(section.Misc_VirtualSize - section.SizeOfRawData),
                                section.VirtualAddress, section.SizeOfRawData, section.PointerToRawData,
                                section.Characteristics, section.get_entropy()])
                    break
            except AttributeError:
                row.extend(["Error", "Error", "Error", "Error", "Error", "Error", "Error", "Error"])
        if reloc_number == 0:
            row.extend(["None", "None", "None", "None", "None", "None", "None", "None"])

        # add total_iat_number
        try:
            pe.parse_data_directories()
            total_iat_number = 0
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    total_iat_number += 1
            row.extend([total_iat_number])
        except AttributeError:
            total_iat_number = 0
            row.extend([total_iat_number])

        # add total_eat_number
        try:
            total_eat_number = 0
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                total_eat_number += 1
            row.extend([total_eat_number])
        except AttributeError:
            total_eat_number = 0
            row.extend([total_eat_number])
        
        try:
            tmp = pe.parse_rich_header()
            row.extend([ 1, tmp['raw_data'] ])
        except:
            row.extend([0,'None'])


        return row

    def Save_Pe_Label():
        with open('./train_label.csv', 'r') as f:
            with open('./pe_features.csv', 'r') as ff:
                with open('./new_pe_features.csv', 'w+', newline='') as fff:
                    cr = csv.reader(f)
                    crr = csv.reader(ff)
                    cw = csv.writer(fff)
                    for line in crr:
                        f.seek(0)
                        for line2 in cr:
                            if line[0] == line2[0]:
                                cw.writerow(line + line2[1:])
                                break
        os.remove('./pe_features.csv')
        shutil.move('./new_pe_features.csv','./pe_features.csv')

if __name__ == "__main__":
    #Making Static PE features
    Save_Pe_Feature()
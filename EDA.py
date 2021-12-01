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
        'rich_header_is_exist', 'raw_rich_header', 'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfInitializedData', 'SizeOfUninitializedData', 'SizeOfStackReserve', 'DllCharacteristics'
    ]

    #Train data based data analysis
    #file_path = './train_data'
    #file_path = './validation_data'
    file_path = './test_data'
    NULL_ROW = [0 for x in COLS]

    def __init__(self, filename, label):
        print("[+] Saving PE File Features")
        files = os.listdir(Save_Pe_Feature.file_path)
        with open(filename, 'w+', newline='') as csvs:
            wp = csv.writer(csvs)
            wp.writerow(Save_Pe_Feature.COLS)
            for idx, file in enumerate(files):
                try:
                    pe = pefile.PE(os.path.join(Save_Pe_Feature.file_path, file) )
                    feature = Save_Pe_Feature.Extract_Pe_Features(pe, file)
                except:
                    print('[+] {} with NULL'.format(file))
                    feature = Save_Pe_Feature.NULL_ROW
                    feature[0] = file
                wp.writerow(feature)
        print("[-] Saving PE File Features - Done")
        if 'test' not in filename:
            Save_Pe_Feature.Save_Pe_Label(filename, label)

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
        
        #add Linker Version, Size of Init / Uninitialized Data, Size of Stack Reserve, DllCharacteristics
        try:
            tmp = pe.parse_rich_header()
            row.extend([ 1, tmp['raw_data'] ])
        except:
            row.extend([0,'None'])

        #Add Major Linker Version
        try:
            row.extend([pe.OPTIONAL_HEADER.MajorLinkerVersion])
        except:
            row.extend(["None"])
        
        #Add Minor Linker Version
        try:
            row.extend([pe.OPTIONAL_HEADER.MinorLinkerVersion])
        except:
            row.extend(["None"])

        #Add Size of initialized data
        try:
            row.extend([pe.OPTIONAL_HEADER.SizeOfInitializedData])
        except:
            row.extend(["None"])

        #Add Size of uninitialized data
        try:
            row.extend([pe.OPTIONAL_HEADER.SizeOfUninitializedData])
        except:
            row.extend(["None"])
        
        #Add Size of stack reserve
        try:
            row.extend([pe.OPTIONAL_HEADER.SizeOfStackReserve])
        except:
            row.extend(["None"])
        
        #Add DLL Characteristics
        try:
            row.extend([pe.OPTIONAL_HEADER.DllCharacteristics])
        except:
            row.extend(["None"])

        return row

    def Save_Pe_Label(filename, label):
        print("[+] Adding Labels")
        if label != '0':
            with open(label, 'r') as f:
                with open(filename, 'r') as ff:
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
            os.remove(filename)
            shutil.move('./new_pe_features.csv',filename)
        else:
            print("[+] This is Test file")
        print("[-] Adding Labels - Done")

if __name__ == "__main__":
    '''
    For Train Set
    './train_data'
    './pe_features.csv'
    './train_label.csv'
    '''
    #Save_Pe_Feature('./pe_features.csv', 'train_label.csv')

    '''
    For Validation Set
    './validation_data'
    './valiation_features.csv'
    './valiation_label.csv'
    '''
    #Save_Pe_Feature('./validation_features.csv', 'validation_label.csv')

    '''
    For Test Set
    './test_data'
    './test_features.csv'
    '''
    Save_Pe_Feature('./test_features.csv', '0')

    #Making Static PE features
    
    
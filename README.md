# Data_Based_Security

### Overview

- Exploratory Dataset Analysis & Malware detection usin boost algorithm
- Use 76 Static Features

<br/>

### how to run?

```
python main.py
```

<br/>

### EDA [Data Refining]

- **PE file Static Analysis** [Input file : File Directory / Output file : pe_features.csv]
  - filename => Not used as a real feature
  - e_magic
  - e_lfanew
  - e_minalloc
  - e_ovno
  - Signature
  - Machine
  - NumberOfSections
  - TimeDateStamp
  - PointerToSymbolTable
  - NumberOfSymbols
  - SizeOfOptionalHeader
  - Characteristics
  - Magic
  - SizeOfCode
  - AddressOfEntryPoint
  - BaseOfCode
  - ImageBase
  - EntryPoint
  - SectionAlignment
  - FileAlignment
  - SizeOfImage
  - SizeOfHeaders
  - CheckSum
  - Subsystem
  - NumberOfRvaAndSizes
  - CompareNumberOfSections
  - .textSectionName
  - .textSectionVirtualSize
  - .textSection|VirtualSize-SizeOfRawData|
  - .textSectionVirtualAddress
  - .textSectionSizeOfRawData
  - .textSectionPointerToRawData
  - .textSectionCharacteristics
  - .textSectionEntropy
  - .dataSectionName
  - .dataSectionVirtualSize
  - .dataSection|VirtualSize-SizeOfRawData|
  - .dataSectionVirtualAddress
  - .dataSectionSizeOfRawData
  - .dataSectionPointerToRawData
  - .dataSectionCharacteristics
  - .dataSectionEntropy
  - .rsrcSectionName
  - .rsrcSectionVirtualSize
  - .rsrcSection|VirtualSize-SizeOfRawData|
  - .rsrcSectionVirtualAddress
  - .rsrcSectionSizeOfRawData
  - .rsrcSectionPointerToRawData
  - .rsrcSectionCharacteristics
  - .rsrcSectionEntropy
  - .rdataSectionName
  - .rdataSectionVirtualSize
  - .rdataSection|VirtualSize-SizeOfRawData|
  - .rdataSectionVirtualAddress
  - .rdataSectionSizeOfRawData
  - .rdataSectionPointerToRawData
  - .rdataSectionCharacteristics
  - .rdataSectionEntropy
  - .relocSectionName
  - .relocSectionVirtualSize
  - .relocSection|VirtualSize-SizeOfRawData|
  - .relocSectionVirtualAddress
  - .relocSectionSizeOfRawData
  - .relocSectionPointerToRawData
  - .relocSectionCharacteristics
  - .relocSectionEntropy
  - TotalNumberOfFunctionInIAT
  - TotalNumberOfFunctionInEAT
  - exist_rich_header
  - raw_rich_header
  - MajorLinkerVersion
  - MinorLinkerVersion
  - SizeOfInitializedData
  - SizeOfUninitializedData
  - SizeOfStackReserve
  - DllCharacteristics

<br/>

### Malware_Classifier [Train & Validation & Test with Malware features]

- **Using Models**
  - xgboost
  - adaboost
  - gbm
  - lgbm
  - catboost

<br/>

- **Code Explanation**
  - **Model** class [Making each Trained models & Saving each models]

    - **Xgboost** function [Implementation of xgboost]

    - **Adaoost** function [Implementation of Adaboost]

    - **GBM** function [Implementation of GBM]

    - **LGBM** function [Implementation of LGBM]

    - **Catboost** function [Implementation of Catboost]

    - **Find_Hyperparameter** function [Hyperparameter finder automatically]

    - **predictions** function (lower case only) [Predictions with test data using target model]

    - **Get_Csv** function [Get Dataset]

    - **Check_Drop** function [drop columns from dataset]

    - **Change_Types** function [Change types for training & MinMax Scaling]

    - **Check_Describe** function [Describe Dataset x]

      <br/>

  - **Model_Validation** class [Get Scores with Validation Dataset using each models]

    - **Check_Xgboost** function [Get score xgboost model with Validation dataset]

    - **Check_Adaboost** function [Get score adaboost model with Validation dataset]

    - **Check_GBM** function [Get score GBM model with Validation dataset]

    - **Check_LGBM** function [Get score LGBM model with Validation dataset]

    - **Check_Catboost** function [Get score catboost model with Validation dataset]

      <br/>

  - **Model_Test** class [Get prediction with Test Dataset using best models]

    - **Input** : Model
    - **Get_Test_Features** function [Get Test Dataset csv file]
    - **Do_Test** function [Do predictions using model]
    - **Save_To_Csv** function [Save predictions to csv file]

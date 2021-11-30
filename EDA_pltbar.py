import csv
from hashlib import new
import matplotlib.pyplot as plt
import numpy
import os
import pefile
import shutil

Normal_Correct = 0
Normal_Num = 0
Mal_Correct = 0
Mal_Num = 0
num = 26

#Compare label number / label
with open('./pe_features.csv', 'r') as f:

    cr = csv.reader(f)
    next(cr)
    for line in cr:
        if line[-1:][0] == '0':
            Normal_Num += 1
            if int(line[num]) == 1:
                Normal_Correct += 1
        else:
            Mal_Num += 1
            if int(line[num]) == 1:
                Mal_Correct += 1



Correction = [Normal_Correct, Mal_Correct]
Number = [Normal_Num, Mal_Num]
label = ['Normal_Data', 'Mal_Data']

plt.figure()

x = numpy.arange(len(label))
plt.bar(x-0.0, Correction, label='rsrcSectionCharacteristics', width=0.2)
plt.bar(x+0.2, Number, label='Number of Datas', width=0.2)
plt.xticks(x, label)

plt.legend()
plt.xlabel('Data')
plt.ylabel('Numbers')
plt.title('Compare Norm/Mal`s number of rsrcSectionCharacteristics')
plt.show()

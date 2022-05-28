import csv
from shutil import copyfile

g = raw_input("Enter your psu ID (e.g. abs1275@psu.edu) : ")
print g
t=0
with open('Create_format_name/names_num.csv') as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    for row in csv_reader:
        t=t+1
        if row[0]==g:
            print('Number for ' + str(g) + ' is: ' + str(row[1]))
            print('t is:' + str(t))
            break

if t == 0:
    print('PSU ID is either invalid or not enrolled the course')
else:
    print('Number for ' + str(g) + ' is: ' + str(row[1]))
    x=int(row[1])
    print('x is:' + str(x))
    print('x is:' + str(x))
    src_f = "Create_format_name/formats/cmpsc473-format-"+str(x)+".h"
    dst_f = "cmpsc473-format-"+str(x)+".h"
    copyfile(src_f, dst_f)
    src_i = "Create_format_name/input_file_rand/input-"+str(x)+".txt.rand"
    dst_i = "input-"+str(x)+".txt.rand"
    copyfile(src_i, dst_i)

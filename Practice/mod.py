import pandas as pd
import csv

def conv(x):
	return 'good' if x == 0 else 'bad'

f = open('dataset.csv')

reader = csv.reader(f, delimiter=',')

c = -1
for row in reader:
	c += 1
	if c == 0:
		print('url','label')
		continue
	print(row[0],conv(row[1]))

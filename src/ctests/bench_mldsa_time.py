import os
import pandas as pd

NumberTrials = 1000

os.system("make clean && make bench_mldsa_time")


operations = [1,2,3]
strengths = [1,2,3]

for op in operations:
    for strength in strengths:
        cmd = "./bench_mldsa_time {} {} 5000".format(op, strength)
        os.system(cmd)

        dataframe = pd.read_csv("bench_mldsa_time.csv")
        datalist = dataframe["nanoseconds"].to_list()
        datalist.sort()
        print("Median runtime in nanoseconds for operation {} at strength {}: ".format(op, strength), datalist[int(len(datalist)/2)])
        
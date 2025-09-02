import os
import pandas as pd


NumberTrials = 1000

os.system("make clean && make bench_dilithium_papi")

# with open("bench_mldsa.csv", "w+") as file: # Clears CSV
#     pass

# for op in [1,2,3]:
#     for strength in [1,2,3]:

#         countIns = 0
#         countCyc = 0

#         with open("bench_mldsa.txt", "w+") as file:

#             cmd = "./bench_mldsa_papi PAPI_TOT_CYC {} {}".format(op, strength)
#             for _ in range(NumberTrials):
#                 os.system(cmd)

#             for line in file:
#                 countCyc += int(line)

#         with open("bench_mldsa.txt", "w+") as file:
#             cmd = "./bench_mldsa_papi PAPI_TOT_INS {} {}".format(op, strength)
#             for _ in range(NumberTrials):
#                 os.system(cmd)

#             for line in file:
#                 countIns += int(line)

#         with open("bench_mldsa.csv", "a") as file:
#             file.write("{},{},{},{}\n".format(op, strength, countCyc/NumberTrials, countIns/NumberTrials))


operations = [1,2,3]
strengths = [1,2,3]

for op in operations:
    for strength in strengths:
        cmd = "./bench_dilithium_papi PAPI_TOT_CYC {} {}".format(op, strength)
        os.system(cmd)

        # with open("bench_dilithium.csv", "r") as file:
        dataframe = pd.read_csv("bench_dilithium.csv")
        datalist = dataframe["cycleCount"].to_list()
        datalist.sort()
        print("Median runtime in nanoseconds for operation {} at strength {}: ".format(op, strength), datalist[int(len(datalist)/2)])
        
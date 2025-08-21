import os


NumberTrials = 1000

os.system("make clean && make bench_mldsa_papi")

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



op = 2
strength = 1

with open("bench_mldsa_signature_{}_no_malloc.csv".format(strength), "w+") as file:

    cmd = "./bench_mldsa_papi PAPI_TOT_INS {} {}".format(op, strength)
    for _ in range(NumberTrials):
        os.system(cmd)
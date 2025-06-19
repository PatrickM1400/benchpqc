
import os

KeyGenCount = 0
SignCount = 0
VerifyCount = 0

NumberTrials = 1000

os.system("make clean && make benchtime")

with open("benchtime.txt", "w+") as file:

    for _ in range(NumberTrials):
        os.system("./benchtime")

    for line in file:
        counts = line[0:-1].split(",")
        KeyGenCount += int(counts[0])
        SignCount += int(counts[1])
        VerifyCount += int(counts[2])

print("Average time for ML-DSA security strength 2 in microsec")
print((KeyGenCount/NumberTrials, SignCount/NumberTrials, VerifyCount/NumberTrials))
    
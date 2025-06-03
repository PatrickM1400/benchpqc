
import os

KeyGenCount = 0
SignCount = 0
VerifyCount = 0

NumberTrials = 1000

os.system("make bench")

with open("benchgen.txt", "w+") as file:

    for _ in range(NumberTrials):
        os.system("./benchgen3")

    for line in file:
        counts = line[0:-1].split(",")
        KeyGenCount += int(counts[0])
        SignCount += int(counts[1])
        VerifyCount += int(counts[2])

print("Average cycles for ML-DSA security strength 3")
print((KeyGenCount/NumberTrials, SignCount/NumberTrials, VerifyCount/NumberTrials))
    
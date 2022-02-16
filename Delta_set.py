import secrets
#generate delta/lambda
def delta_set():
    #generate random number for passive bytes
    rand_int = secrets.randbelow(256)
    all = []
    #256 states
    for k in range(256):
        grid = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                #the first index is the active index which goes from 0 - 255
                if (i == 0) and (j == 0):
                    grid[i].append(k)
                #all the other indices are given the value of 0
                else:
                    grid[i].append(rand_int)
        all.append(grid)
    return all

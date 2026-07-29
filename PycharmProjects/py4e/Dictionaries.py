# Ch 9 Dictionaries
# 4:29:01
# in memory database, key and value.

# This creates an empty dictionary.
purse = dict()
purse['money'] = 12
purse['candy'] = 3
purse['tissues'] = 75
print(purse)

# Another way, to create a dictionary
jjj = {'chuck' : 1, 'fred' : 42, 'jan' : 100}

# Another empty dictionary
ooo = {}


# Counting
counts = dict()
names = ['csev', 'cwen', 'csev', 'zqian', 'cwen']
for name in names :
    if name not in counts:
        counts[name] = 1
    else :
        counts[name] = counts[name] + 1
print(counts)

# The same using get
counts = dict()
names = ['csev', 'cwen', 'csev', 'zqian', 'cwen']
for name in names :
    counts[name] = counts.get(name, 0) + 1
print(counts)

# Counting Words in Text
counts = dict()
print('Enter a line of text:')
line = input('')

words = line.split()

print('Words:', words)

print('Counting ....')
for word in words:
    counts[word] = counts.get(word,0) + 1
print('Counts', counts)


# Loops and Dictionaries
counts = {'chuck' : 1, 'fred' : 42, 'jan' : 100}
for key in counts :
    print(key, counts[key])

# to get only the keys.
print(counts.keys())

# To get only the values.
print(counts.values())

# To get key and value.
print(counts.items())


# counting words in file.
name = input('Enter file: ')
handle = open(name)

counts = dict()
for line in handle:
    words = line.split()
    for word in words:
        counts[word] = counts.get(word,0) + 1

bigcount = None
bigword = None
for word,count in counts.items():
    if bigcount is None or count > bigcount:
        bigword = word
        bigcount = count

print(bigword, bigcount)



# Counting Word Frequency using a Dictionary.
# Ch 9. 4:57:40

fname = input('Enter File: ')
if len(fname) < 1 : fname = 'clown.txt'
hand = open(fname)

di = dict()
for lin in hand:
    lin = lin.rstrip()
    # print(lin)
    wds = lin.split()
    # print(wds)
    for w in wds:
        # print(w)
        # Get method check if word is in dictionary and assing default value of -99
        # print('**',w,di.get(w,-99))

        # if the key is not there the count is zero.
        oldcount = di.get(w,0)
        print(w,'old',oldcount)
        newcount = oldcount + 1
        di[w] = newcount
        print(w,'new',newcount)

        # All before can be combined in the following that is idiom
        # idiom: retrieve/create/update counter all in one line.
        di[w] = di.get(w,0) + 1
        print(w,'new',di[w])


        # All if was replaced by get method.
        # if w in di :
            # di[w] = di[w] + 1
            # print('** Existing **')
        # else:
            # di[w] = 1
            # print('*** NEW ***')
        # print(w,di[w])
        # print(di[w])

# To get all counts
print(di)

# now we want to find the most common word.
# items returns the key and value, you need to variables to pick the values.
largest = -1
theword = None
for k,v in di.items() :
    print(k,v)
    if v > largest :
        largest = v
        theword = k #capture/remember the key that was largest.

print('Done',theword,largest)


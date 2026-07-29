name = input('Enter file:')
handle = open(name,'r')

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

fhandle = open(mbox-short.txt)
for line in fhandle:
    line = line.rstrip()
    if line.startswith('From'):
        print(line)


for line in fhandle:
    line = line.rstrip()
    if not line.startswith('From'):
        continue
    print(line)


for line in fhandle:
    line = line.rstrip()
    if not '@uct.ac.za' in line:
        continue
    print(line)

fname = input('Enter the file name: ')
fhandle = open(fname)
count = 0
for line in fhandle:
    if line.startswith('Subject'):
        count = count +1
print('there were', count,'subject lines in', fhandle)


# Bad File Names
fname = input('Enter the file name: ')
try:
    fhandle = open(fname)
except:
    print('File cannot be opened:', fname)
    quit()

count = 0
for line in fhandle:
    if line.startswith('Subject'):
        count = count + 1
print('there were', count, 'sunject lines in' fname)


total = 0
count = 0
while True :
    inp = input('Enter a number: ')
    if inp == 'done' : break
    value = float(inp)
    total = total + value
    count = count + 1

average = total / count
print('Average:',average)

numlist = list()
while True :
    inp = input('Enter a number: ')
    if inp == 'done' : break
    value = float(inp)
    numlist.append(value)

average = sum(numlist) / len(numlist)
print('Average:', average)

fhandle = open('mbox-short.txt')
for line in fhandle:
    line = line.rstrip()
    if not line.startswith('From') : continue
    words = line.split()
    print(words[2])

words = line.split()
email = words[1]
pieces = email.split('@')
print(pieces[1])




han = open('mbox-short.txt')

for line in han:
    lien = line.rstrip()
    wds = line.split()
    # Guardian patter
    if len(wds) < 1 :
        continue

    if wds[0] != 'From' :
        continue
    print(wds[2])


# Another way to do the same is to skip a blank line.

han = open('mbox-short.txt')

for line in han:
    line = line.rstrip()
    # Guardian patter
    if line == '' :
        continue
    wds = line.split()

    if wds[0] != 'From' :
        continue
    print(wds[2])


# Another way to do the same is to skip a blank line.
# and Guardian a bit stronger
han = open('mbox-short.txt')

for line in han:
    lien = line.rstrip()
    wds = line.split()
    # Guardian a bit stronger
    if len(wds) < 3 :
        continue

    if wds[0] != 'From' :
        continue
    print(wds[2])



# Another way to do the same is to skip a blank line.
# and Guardian a bit stronger
han = open('mbox-short.txt')

for line in han:
    line = line.rstrip()
    wds = line.split()
    # Guardian in a compound statement
    # You need the correct order, if not can fail.
    if len(wds) < 3 or wds[0] != 'From' :
        continue
    print(wds[2])


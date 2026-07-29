'''
Python Regular Expression Quick Guide


.        Matches any character, except new line
\d       Digit (0-9)
\D       Not a Digit (0-9)
\w       Matches a Word Character (a-z, A-Z, 0-9, _)
\W       Not a Word Character
\s       Matches whitespace (space, tab, newline)
\S       Matches any non-whitespace character
\b       Matches Word Boundary
\B       Not a Word Boundary

^        Matches the beginning of a line/string
$        Matches the end of the line/string
[]       Matches characters in brackets
[^ ]     Matches characters NOT in
|        Either (Or)
( )      Group

Quantifiers:
*        Repeats a character zero or more times
+        Repeats a character one or more times
?        Repeats a character zero or one, it make the character optional.
{3}      Exact number (repeat the number of times specified.
{3,4}    Repeat 3 or 4 time.

*?       Repeats a character zero or more times
         (non-greedy)

+?       Repeats a character one or more times
         (non-greedy)
[aeiou]  Matches a single character in the listed set
[^XYZ]   Matches a single character not in the listed set
[a-z0-9] The set of characters can include a range
(        Indicates where string extraction is to start
)        Indicates where string extraction is to end

'''

# Before you use Regular Expressions you must import the library.
import re
re.search() # to see if a string matches a regular expression.
re.findall() # to extract portions of a string.

re.finditer() #
# the match has an object  group.

import re

hand = open('mbox-short.txt')
for line in hand :
    line = line.rstrip()
    if re.search('^From',line)
        print(line)

# Tu get the email address from the text.
y = re.findall('\S+@\S+',x)
print(y)

# The following match the line that start with From, but extract what is inside ( )
y = re.findall('^From (\S+@\S+)' ,x)

'^From .*@([^ ]*)'
# [^ ] match non-blank character.

# If you look for the real $ sign, you must use \ in the front.
# \$

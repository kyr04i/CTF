# Bandit
# Level 4 -> 5
# Goal
> The password for the next level is stored in the only human-readable file in the inhere directory. Tip: if your terminal is messed up, try the “reset” command.

# WriteUp:

```
bandit4@bandit:~/inhere$ file -- *
-file00: data
-file01: data
-file02: data
-file03: data
-file04: data
-file05: Non-ISO extended-ASCII text, with NEL line terminators
-file06: Non-ISO extended-ASCII text, with no line terminators, with escape sequences
-file07: ASCII text
-file08: data
-file09: data

bandit4@bandit:~/inhere$ cat ./-file07
lrIWWI6bB37kxfiCQZqUdOIYfr6eEeqR
```

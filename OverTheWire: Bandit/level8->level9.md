# Bandit
# Level 8 -> 9
# Goal
> The password for the next level is stored in the file data.txt and is the only line of text that occurs only once
# WriteUp:

```
bandit8@bandit:~$ cat data.txt | sort | uniq -u
EN632PlfYiZbn3PhVK3XOGSlNInNE00t
```

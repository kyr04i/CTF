# Bandit
# Level 9 -> 10
# Goal
> The password for the next level is stored in the file data.txt in one of the few human-readable strings, preceded by several ‘=’ characters.
# WriteUp:

```
bandit9@bandit:~$ strings data.txt | grep "=="
f========== theM
========== password
========== is
========== G7w8LIi6J3kTb8A7j9LgrywtEUlyyp6s
========== G7w8LIi6J3kTb8A7j9LgrywtEUlyyp6s
```

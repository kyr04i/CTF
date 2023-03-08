# Bandit
# Level 10 -> 11
# Goal
> The password for the next level is stored in the file data.txt, which contains base64 encoded data
# Write Up:

```
bandit10@bandit:~$ ls
data.txt

bandit10@bandit:~$ cat data.txt
VGhlIHBhc3N3b3JkIGlzIDZ6UGV6aUxkUjJSS05kTllGTmI2blZDS3pwaGxYSEJNCg==

bandit10@bandit:~$ echo "VGhlIHBhc3N3b3JkIGlzIDZ6UGV6aUxkUjJSS05kTllGTmI2blZDS3pwaGxYSEJNCg==" | base64 -d
The password is `6zPeziLdR2RKNdNYFNb6nVCKzphlXHBM`

```

# Bandit
# Level 5 -> 6
# Goal
> The password for the next level is stored in a file somewhere under the inhere directory and has all of the following properties:

human-readable
1033 bytes in size
not executable
# WriteUp:

`
bandit5@bandit:~/inhere$ find . -type f -size 1033c ! -executable -exec file {} + | grep ASCII
./maybehere07/.file2: ASCII text, with very long lines (1000)
bandit5@bandit:~/inhere$ cat ./maybehere07/.file2
P4L4vucdmLnm8I7Vl7jG1ApGSfjYKqJU
`
# Bandit
# Level 0 -> 1 
# Goal
> The password for the next level is stored in a file called readme located in the home directory. Use this password to log into bandit1 using SSH. Whenever you find a password for a level, use SSH (on port 2220) to log into that level and continue the game.

# WriteUp:

`
bandit0@bandit:~$ ls
readme

bandit0@bandit:~$ cat readme
NH2SXQwcBdpmTEzi3bvBHMM9H66vVXjL

ssh bandit1@bandit.labs.overthewire.org -p 2220

->bandit1@bandit.labs.overthewire.org's password:NH2SXQwcBdpmTEzi3bvBHMM9H66vVXjL
`

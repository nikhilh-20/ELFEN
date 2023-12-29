374e76244ff579278f294a3b70bed0b27c7d089d101d9eb97af26a04c33a5bd2: ELF64, Hello World program
102e68c030aa7a57c3cfb554904c335483575998335d14ac8c6d032fd732ab3d: ELF64, Hello World program
44a19f785c695a90f7ace5d17feb25a7c7e95f9ce609117138c739276fc145ff: ELF64, Hello World program, stripped
a7df93896cced4e217d696b6b0bbfb259ded4e80d05652c31646e7b4b86827ab: ELF64, Severely truncated Hello World program, does not execute
1a0de3871be4932abd0ace0dd12cd90a7c1cd27747612174d03c9dfe287ad0da: ELF64, Concat of 374e76244ff579278f294a3b70bed0b27c7d089d101d9eb97af26a04c33a5bd2, a7df93896cced4e217d696b6b0bbfb259ded4e80d05652c31646e7b4b86827ab
94d442a6511f8430e16f3bad31d3e3e81cfed72fe32450a294c8606963fd47d1: ELF64, Compiled RC4 program copied from https://hideandsec.sh/books/red-teaming/page/the-rc4-encryption
1eac86dd4dde2fdc06cb7b8d9dbe2573eff4cc7bc428f1a1c0aed65a80fad428: ELF64, Same as 374e76244ff579278f294a3b70bed0b27c7d089d101d9eb97af26a04c33a5bd2 except some sections-related fields in the ELF header were zero'd
870dfc01d8c1008f7ae2cf7d8fb9b757f8e7e2710ce575b9308692a197aaeef7: ELF64, Binary to test calls to open(), read(), write(), rename(), readlink(), unlink()
283bc45807be383ab51b7100c4c90d989a11c5e882488d033a73ccddf3c34a76: ELF64, Binary to test calls to fcntl()
ec399f4c159c07e8f7a89a7da1cc700bc17d8ccd600b7e5a56bd36bb77b622a6: ELF64, Binary to test calls to fork(), getpid(), getppid(), execve(), prctl()
d69177f28e1b9079053e30dbc67fffdece2439850b4c4c2df53c0af33b6e6125: ELF64, Binary to test calls to socket(), setsockopt(), bind(), connect(), listen()
e4d10b0142721c42d55f2bfa975003981d20058eccf577939180aa5f0fa0c4dd: ELF64, Binary to test calls to libc functions - strcmp(), strncmp(), strstr(), strcpy(), strncpy()
c563067392e6ff7ee1a668ecb695d9f449bb7c4c60693d4505be87297d9118ce: ELF64, Binary to test calls to sendto(), recvfrom()
a1e185bce8ac11ffc435103f1401061dbc1ce1209f43a5efaaa12d5db20ec5d0: ELF64, Yara test binary
65c0f964cade2e4850619343662d2c578a3c188ffdd5f9bbbfead9d97d11f9a7: ELF64, Binary to test DNS resolution

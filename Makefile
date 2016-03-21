
reverse_switch-case:
	clang -no-integrated-as -DSCRYPT_CHACHA -DSCRYPT_BLAKE512 main.c bctf.c scrypt-jane.c -o $@
	strip $@


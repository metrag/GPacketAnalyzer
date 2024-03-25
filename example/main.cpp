#include <iostream>
#include <string>
#include <cstdio>
#include <cstdlib>

using namespace std;

int main(int argc, char* argv[]){
	string path = (string)argv[0] + ".txt";
	
	if(argc > 1){
		path = (string)argv[1];
	}

	cout << path << endl;
	
	char* name = strdup(path);
	cout << name;
/*
	ifstream fin(path);
	
	//char ch;
	string str;
	while(!fin.eof()){
		getline(fin, str);
		cout << str << endl;
	}
	fin.close();
*/
}

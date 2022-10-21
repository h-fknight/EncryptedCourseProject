#include"SHA1.hpp"
#include <string>
#include <iostream>
using namespace std;

int main() {

    string input = "abc";
    SHA1 checksum;
    checksum.update(input);
    string hash = checksum.final();
    cout << "The SHA-1 of \"" << input << "\" is: " << hash << endl;
    checksum.update("asdasdas");
    string hash3 = checksum.final();
    cout << "The SHA-1 of \"" << "asdasdas" << "\" is: " << hash3 << endl;

    string hash2 = checksum.from_file("d:\\flower.docx");
    cout << hash2<<endl;

    return 0;


}
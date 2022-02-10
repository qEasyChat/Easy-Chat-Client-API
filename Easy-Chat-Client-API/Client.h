#pragma once
#pragma comment( lib, "ws2_32.lib")

#include <thread>
#include <iostream>
#include <string>

#include <winsock2.h>

#include "Connection.h"
#include "Crypto_Manager.h"

#ifdef CLIENT_EXPORTS
	#define CLIENT_API __declspec(dllexport)
#else
	#define CLIENT_API __declspec(dllimport)
#endif

class CLIENT_API Server_Down_Exception : public std::exception {
public:
	virtual const char* what() const throw() {
		return "Server is down";
	}private:
};

class CLIENT_API Login_Exception : public std::exception {
public:
	virtual const char* what() const throw() {
		return "Authentification failed";
	}
private:
};

class CLIENT_API Client
{
public:
	Client(int port_number, const std::string ip);
	~Client();

	void connect_and_auth(std::string username, std::string password);
	void start_reciver();
	void sender();

	std::string get_server_name();
	void set_server_name(std::string server_name);

	std::string recive_message();
	void send_message(std::string message);

private:
	std::string server_name;
	std::thread reciver;

	std::shared_ptr<Connection> server_connection;
	struct sockaddr_in server_addr;

	Crypto_Manager crypto_manager;

	void connect_to_server();
	void authentification(std::string username, std::string password);
};


#include "pch.h"

#define CLIENT_EXPORTS
#include "Client.h"

#include "Crypto_Manager.h"
#include "Utils.h"

Client::Client(int port_number, const std::string ip)
{
	this->server_connection = std::shared_ptr<Connection>(new Connection(port_number, ip));
	if(this->server_connection == nullptr)
	{
		Utils::memory_error();
	}
	std::memset(server_addr.sin_zero, '\0', sizeof(server_addr.sin_zero));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port_number);
	server_addr.sin_addr.s_addr = inet_addr(ip.c_str());
}

Client::~Client() {
	if (reciver.joinable()) {
		reciver.join();
	}
	this->server_name = "";
	this->server_connection.reset();
}

void Client::connect_and_auth(std::string username, std::string password) {
	try
	{
		connect_to_server();
	}
	catch (Server_Down_Exception exception)
	{
		std::cerr << "server is down" << std::endl;
		exit(EXIT_FAILURE);
	}

	try
	{
		authentification(username, password);
	}
	catch (Login_Exception exception)
	{
		std::cerr << "authentification was not successful" << std::endl;
		exit(EXIT_FAILURE);
	}
}

void Client::connect_to_server()
{
	SOCKET client_socket = this->server_connection->get_socket();

	if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
		throw Server_Down_Exception();
	}
	std::cout << "connection was successful" << std::endl;

}

void Client::authentification(std::string username, std::string password)
{
	std::string password_hash = crypto_manager.get_sha3_512_hash(password);
	this->server_connection->send_message(username);
	this->server_connection->send_message(password_hash);
	this->server_name = this->server_connection->recive_message();
	
	std::string login_response = this->server_connection->recive_message();
	if (login_response == "RETRY") {
		throw Login_Exception();
	}
	std::cout << "login was successful" << std::endl;
	this->server_connection->set_username(username);
}

void Client::start_reciver()
{
	this->reciver = std::thread(&Client::recive_message, this);
}

std::string Client::recive_message() {
	std::string message = "";
	while (message!= "SOCKET_DOWN") {
		message = this->server_connection->recive_message();
		if(message != "" || message != "\n")
		{
			return message;
		}
	}
}

void Client::sender() {
	while (true) {
		std::string message = "";
		std::getline(std::cin, message);
		this->send_message(message);
	}
}

void Client::send_message(std::string message)
{
	this->server_connection->send_message(message);
}


std::string Client::get_server_name()
{
	return this->server_name;
}

void Client::set_server_name(std::string server_name)
{
	this->server_name = server_name;
}

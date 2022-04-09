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
	if (recive_thread.joinable()) {
		recive_thread.join();
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
	this->recive_thread = std::thread(&Client::reciver, this);
}

void Client::reciver()
{
	std::string message = "";
	while (message != "SOCKET_DOWN") {
		message = this->recive_message();
		if (!message.empty())
		{
			std::cout << message << std::endl;
		}
	}
}


std::string Client::recive_message() {
	std::string message = this->server_connection->recive_message();
	if (message != "" || message != "\n")
	{
		return message;
	}
	return NULL;
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



void Client::send_file(std::string file_path)
{
	FILE* file = fopen(file_path.c_str(), "rb");
	size_t file_size = ftell(file);
	rewind(file);
	std::string header = "FILE " + file_path + " " + std::to_string(file_size);
	send_message(header);
	if (file_size > 0)
	{
		char buffer[1024];
		do
		{
			size_t num = std::min(file_size, sizeof(buffer));
			num = fread(buffer, 1, num, file);
			if (num < 1)
			{
				break;;
			}
			send_message(buffer);
			file_size -= num;
		} while (file_size > 0);
	}
	fclose(file);
}

void Client::recive_file()
{
	std::string header = recive_message();
	std::vector<std::string> header_args = Utils::string_to_vector<std::string>(header);
	std::string file_name = header_args[1];
	size_t file_size = std::stoi(header_args[2]);
	FILE* file = fopen(file_name.c_str(), "wb");
	if (file_size > 0)
	{
		char buffer[1024];
		std::string file_str = recive_message();
		fwrite(&buffer, file_str.size(), file_str.size(), file);
	}
	fclose(file);
}

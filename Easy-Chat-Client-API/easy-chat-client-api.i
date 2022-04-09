%module easy_chat_client_api
 
 %include <std_string.i>
%{
    #include "Client.h"
%}
 
%include <windows.i>
%include "Client.h"
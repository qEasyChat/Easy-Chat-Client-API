%module easy_chat_utils_api
 
 %include <std_string.i>
%{
    #include "Connection.h"
    #include "Crypto_Manager.h"
%}
 
%include <windows.i>
%include "Connection.h"
%include "Crypto_Manager.h"
/** Check if we have multiple cores */
#if CONFIG_FREERTOS_UNICORE
#define ARDUINO_RUNNING_CORE 0
#else
#define ARDUINO_RUNNING_CORE 1
#endif

#define MAX_CLIENTS 1

// Include certificate data (see note above)
#include "config.h"
#include "cert.h"
#include "private_key.h"

// We will use wifi
#include <Arduino.h>
#include <WiFi.h>

// Includes for the server
#include <HTTPSServer.hpp>
#include <SSLCert.hpp>
#include <HTTPRequest.hpp>
#include <HTTPResponse.hpp>
#include <WebsocketHandler.hpp>
#include <string>
#include <sstream>

// The HTTPS Server comes in a separate namespace. For easier use, include it here.
using namespace httpsserver;

#define HEADER_USERNAME "X-USERNAME"
#define HEADER_GROUP    "X-GROUP"

// Create an SSL certificate object from the files included above
SSLCert cert = SSLCert(
  ESP32_1_crt_DER, ESP32_1_crt_DER_len,
  ESP32_1_key_DER, ESP32_1_key_DER_len
);

// Create an SSL-enabled server that uses the certificate
HTTPSServer secureServer = HTTPSServer(&cert);

HardwareSerial Serial_one(1);
HardwareSerial Serial_two(2);
HardwareSerial* COM[1] = {&Serial_one};
bool _escape = false;
uint8_t b;
uint8_t _pos;
uint16_t length;
uint8_t checksumtotal;
int checksumtotal2;
uint8_t result;
uint8_t porttowrite;
uint64_t rxaddress = 0;
uint64_t XBEEADDR[2] = {0x0013A20042313DAF, 0x0013A20042313A35};
uint64_t XBEEADDR1 = 0x0013A20042313DAF; //LOCAL_DEVICE
uint64_t XBEEADDR2 = 0x0013A20042313A35; //REMOTE_DEVICE
uint64_t MYADDRESS = 0xFFFFFFFFFFFFFFFF;
uint64_t SENDADDRESS;

uint8_t SUCCESSFUL_TX = 11;
uint8_t SUCCESSFUL_RX = 12;
uint8_t FAILURE = 13;

uint8_t buf1[BUFFERSIZE];
uint8_t buf2[BUFFERSIZE];
uint8_t txpacket[274];

uint16_t i1 = 0;
uint16_t i2 = 0;

std::ostringstream ss;
std::string msg;

// Declare some handler functions for the various URLs on the server
void handleRoot(HTTPRequest * req, HTTPResponse * res);
void handleInternalPage(HTTPRequest * req, HTTPResponse * res);
void handle404(HTTPRequest * req, HTTPResponse * res);

void middlewareAuthentication(HTTPRequest * req, HTTPResponse * res, std::function<void()> next);
void middlewareAuthorization(HTTPRequest * req, HTTPResponse * res, std::function<void()> next);

// We declare a function that will be the entry-point for the task that is going to be
// created.
void serverTask(void *params);

class ChatHandler : public WebsocketHandler {
public:
  // This method is called by the webserver to instantiate a new handler for each
  // client that connects to the websocket endpoint
  static WebsocketHandler* create();

  // This method is called when a message arrives
  void onMessage(WebsocketInputStreambuf * input);

  // Handler function on connection close
  void onClose();
};

// Simple array to store the active clients:
ChatHandler* activeClients[MAX_CLIENTS];

unsigned long start = millis();

void reset(){
	_pos = 0;
	_escape = false;
	checksumtotal2 = 0;
  length = 0;
  i2 = 0;
  result = 0;
  rxaddress = 0;
}

void sendByte_(uint8_t b, bool escape) {

	if (escape && (b == START_BYTE || b == ESCAPE)) {
    COM[0]->write(0x7d);
    Serial.printf("%02X", 0x7d);
		COM[0]->write(b ^ 0x20);
    Serial.printf("%02X", b ^ 0x20);
	} else {
		COM[0]->write(b);
    Serial.printf("%02X", b);
	}
}

uint8_t readPacket_() {
    //Resets all buffers and flags
    reset();

    //Starts reading the packet if the serial port indicates it has data waiting to be read
    while (COM[0]->available()) {

        b = COM[0]->read();
        Serial.print(b);

        if (_pos > 0 && b == START_BYTE) {
        	//If a new packet starts before the previous packeted completed -- discard the previous packet and start over
        	Serial.print("UNEXPECTED START BYTE\n");
        	return 0;
        }


		if (_pos > 0 && b == ESCAPE) {
			if (COM[0]->available()) {
				b = COM[0]->read();
				b = 0x20 ^ b;
			} else {
				//next byte will be escaped, but it is not yet available
				_escape = true;
				continue;
			}
		}

		if (_escape == true) {
			b = 0x20 ^ b;
			_escape = false;
		}

		// checksum includes all bytes starting with api id
		if (_pos >= 3) {
			checksumtotal2+= b;
		}

        switch(_pos) {
			case 0:
		        if (b == START_BYTE) {
		        	_pos++;
		        }

		        break;
			case 1:
				// length msb
				length = b << 8;
				_pos++;

				break;
			case 2:
				// length lsb
				length = length | b;
				_pos++;

				break;
			case 3:
      //Checks if the received frame is a transmit status frame
				if(b == 0x8B){
          while (_pos < 8){
            if (COM[0]->available()) {
				        b = COM[0]->read();
                checksumtotal2 += b;
                _pos++;
            }
          }

          //Checks if the frame was received correctly and with a successful transmission flag
          if (b==0){
            result = SUCCESSFUL_TX;
            b = COM[0]->read();
            checksumtotal2 += b;
            b = COM[0]->read();
            if((b + (uint8_t)checksumtotal2)==0xFF){
              return 1;
            }
            else{
              return 0;
            }
          }

          else{
            Serial.print("Error");
            Serial.print(b);
            Serial.print(" ");
            result = FAILURE;
            return 0;
          }


        }

        else if(b == 0x88){
          while (_pos < 7){
            Serial.println(_pos);
            if (COM[0]->available()) {
				        b = COM[0]->read();
                checksumtotal2 += b;
                _pos++;
            }
          }

          if (b==0){ 
            while(_pos < 11){
              Serial.println(_pos);
              b = COM[0]->read();
              checksumtotal2 += b; 
              buf2[_pos-7] = b;
					    _pos++;
            }

            b = COM[0]->read();
            if ((b + (uint8_t)checksumtotal2)==0xFF){
              result = SUCCESSFUL_RX;
              return 1;
            }
          }

          else{
            result = FAILURE;
            return 0;
          }
        }
        
        else if(b != 0x90){
          return FAILURE;
        }

        else{
          _pos++;
        }

        break;

      //Reads the rxaddress a byte at a time
      case 4 ... 11:
        rxaddress = rxaddress | (b << (56 - ((_pos-4)*8)));
        _pos++;

        break;

      //Unused fields
      case 12 ... 14:
        _pos++;
        //do nothing
        
        break;

			default:
				//Starts at fifth byte

				if (_pos > MAX_FRAME_DATA_SIZE) {
					// Frame has exceeded max size.  Should never occur
					Serial.print("Payload exceeds max size");
					return 0;
				}

				// Checks if the end of the frame has been reached
				// Packet length does not include start, length, or checksum bytes, so add 3
				if (_pos == (length + 3)) {
					// Verify checksum

					if (((uint8_t)checksumtotal2 & 0xff) == 0xff) {
						
            result = SUCCESSFUL_RX;

					} else {
						// checksum failed
						result = FAILURE;
					}

					// Minus 15 due to the previous fields
				  i2 = _pos - 15;

					// reset state vars
					_pos = 0;

					return 1;

				} else {
					// add to packet array, starting with the fourth byte of the apiFrame
					buf2[_pos-15] = b;
					_pos++;
				}
        }
    }

    return 0;
}

uint8_t readPacket_(int timeout) {

	if (timeout < 0) {
		return 0;
	}

	unsigned long start = millis();

    while (int((millis() - start)) < timeout) {

     	if (readPacket_()){
        return 1;
      }
    }

    // timed out
    return false;
}

uint8_t queryAddress(){
  sendByte_(START_BYTE, false);
  sendByte_(0x00, true);
  sendByte_(0x04, true);
  sendByte_(0x08, true);
  sendByte_(0x01, true);
  sendByte_(0x53, true);
  sendByte_(0x48, true);
  sendByte_(0x5B, true);
  if (readPacket_(5000)){
    if(result == SUCCESSFUL_RX){
      for(int i = 0; i < 4; i++){
        MYADDRESS = (MYADDRESS << 8) | buf2[i];
      }
    }
  }

  sendByte_(START_BYTE, false);
  sendByte_(0x00, true);
  sendByte_(0x04, true);
  sendByte_(0x08, true);
  sendByte_(0x01, true);
  sendByte_(0x53, true);
  sendByte_(0x4C, true);
  sendByte_(0x57, true);

  if (readPacket_(5000)){
    if(result == SUCCESSFUL_RX){
      for(int i = 0; i < 4; i++){
        MYADDRESS = (MYADDRESS << 8) | buf2[i];
      }

      for(int i = 0; i < 2; i++){
        if(XBEEADDR[i]!=MYADDRESS){
          SENDADDRESS = XBEEADDR[i];
          Serial.printf("I am %llX\n", MYADDRESS);
          return 1;
        }
      }
    }
  }

  else{
    Serial.println("Failed here");
    return 0;
  }
  return 0;
}

void sendPacket_(uint64_t address, uint8_t *payload, uint16_t length){
  Serial.printf("Entered sendPacket_, %llX, %ld\n", address, length);
  if (length<256){
    checksumtotal = 0;
    checksumtotal2 = 0;
    for(int i=0; i<110; i++){
      switch(i){
        
        //Sends initial start byte
        case 0:
        sendByte_(START_BYTE, false);
        break;

        //Sends the first 8 bits of the length of the payload
        case 1:
        sendByte_((((length + 14) >> 8) & 0xFF), true);
        break;

        //Sends the remaning 8 bits of the length of the payload
        case 2:
        sendByte_(((length + 14) & 0xFF), true);
        break;

        //Indicates a transmit request frame is being sent
        case 3:
        b = 0x10;
        checksumtotal += b;
        checksumtotal2 += b;
        sendByte_(b, true);
        break;

        //Sets the frame ID to 1
        case 4:
        b = 0x01;
        checksumtotal += b;
        checksumtotal2 += b;
        sendByte_(b, true);
        break;

        //Sends the 64 bit address 8 bits at a time
        case 5:
        b = (address >> 56) & 0xFF;
        checksumtotal += b;
        checksumtotal2 += b;
        sendByte_(b, true);
        break;

        case 6:
        b = (address >> 48) & 0xFF;
        checksumtotal += b;
        checksumtotal2 += b;
        sendByte_(b, true);
        break;

        case 7:
        b = (address >> 40) & 0xFF;
        checksumtotal += b;
        checksumtotal2 += b;
        sendByte_(b, true);
        break;

        case 8:
        b = (address >> 32) & 0xFF;
        checksumtotal += b;
        checksumtotal2 += b;
        sendByte_(b, true);
        break;

        case 9:
        b = (address >> 24) & 0xFF;
        checksumtotal += b;
        checksumtotal2 += b;
        sendByte_(b, true);
        break;

        case 10:
        b = (address >> 16) & 0xFF;
        checksumtotal += b;
        checksumtotal2 += b;
        sendByte_(b, true);
        break;

        case 11:
        b = (address >> 8) & 0xFF;
        checksumtotal += b;
        checksumtotal2 += b;
        sendByte_(b, true);
        break;

        case 12:
        b = address & 0xFF;
        checksumtotal += b;
        checksumtotal2 += b;
        sendByte_(b, true);
        break;

        //Unused field
        case 13:
        b = 0xFF;
        checksumtotal += b;
        checksumtotal2 += b;
        sendByte_(b, true);
        break;

        //Unused field
        case 14:
        b = 0xFE;
        checksumtotal += b;
        checksumtotal2 += b;
        sendByte_(b, true);
        break;

        //Sets the maximum number of hops to the network default
        case 15:
        b = 0x00;
        checksumtotal += b;
        checksumtotal2 += b;
        sendByte_(b, true);
        break;

        //Sets the transmit options to the network default
        case 16:
        b = 0x00;
        checksumtotal += b;
        checksumtotal2 += b;
        sendByte_(b, true);
        break;

        default:
        
        //If the end of the frame has been reached, the checksum is sent, and sending terminates
        if(i== length + 17){
          sendByte_((0xFF - checksumtotal), true);
          printf("\n%x, %x\n", checksumtotal, checksumtotal2);
          return;
        }

        //The payload is sent byte by byte
        else{
          b = payload[i - 17];
          checksumtotal += b;
          checksumtotal2 += b;
          sendByte_(b, true);
        }
      }
    }
  }
}

void pingPong(){
  unsigned long starttime = millis();
  int TRIED = 0;
  int PING_R= 0;
  int PONG_R = 0;
  int SENT = 0; 
  unsigned long timetaken;
  
  while(!(PING_R && PONG_R && SENT)){
    if(!PONG_R){
      if(TRIED && ((millis()-starttime)>5000)){
        starttime=millis();
        sendPacket_(SENDADDRESS, (uint8_t *)"PING", 4);
      }

      else if(!TRIED){
        starttime=millis();
        sendPacket_(SENDADDRESS, (uint8_t *)"PING", 4);
        TRIED = 1;
      }
    }

    if(!(PING_R && PONG_R)){
      if(COM[0]!=NULL){
        readPacket_();
        if (result==SUCCESSFUL_RX){
          msg.assign((char *)buf2, i2);
          if(msg == "PING"){
            Serial.println("PING RECEIVED");
            sendPacket_(SENDADDRESS, (uint8_t *)"PONG", 4);
            PING_R = 1;
            msg.clear();
            msg.shrink_to_fit();
          }

          else if(msg == "PONG"){
            Serial.println("PONG RECEIVED");
            Serial.println((std::to_string(millis()-starttime)).c_str());
            timetaken = millis() - starttime;
            PONG_R = 1; 
          }
        }
      }
    }

    if(PONG_R && !SENT){
      for(int i = 0; i < MAX_CLIENTS; i++) {
        if (activeClients[i] != nullptr) {
          activeClients[i]->send(std::to_string(timetaken), 2);
          SENT = 1;
        }
      }
    }
  }

  msg.clear();
  msg.shrink_to_fit();
            
  i2=0;
}

void setup() {
  // For logging
  Serial.begin(9600);
  Serial.print("ESP32_1");

  WiFi.setHostname("ESP32_1"); 

  WiFi.mode(WIFI_AP);
  WiFi.softAP(SSID, PASSWD);  // configure SSID and password for softAP
  delay(10000);            // VERY IMPORTANT
  WiFi.softAPConfig(STATIC_IP, STATIC_IP, NETMASK);  // configure ip address for softAP

  COM[0]->begin(UART_BAUD1, SERIAL_PARAM1, SERIAL1_RXPIN, SERIAL1_TXPIN);

  Serial.print("Connected. IP=");
  Serial.println(WiFi.softAPIP());

  for(int i = 0; i < MAX_CLIENTS; i++) activeClients[i] = nullptr;

  queryAddress();

  // Setup the server as a separate task.
  Serial.println("Creating server task... ");
  // We pass:
  // serverTask - the function that should be run as separate task
  // "https443" - a name for the task (mainly used for logging)
  // 6144       - stack size in byte. If you want up to four clients, you should
  //              not go below 6kB. If your stack is too small, you will encounter
  //              Panic and stack canary exceptions, usually during the call to
  //              SSL_accept.
  xTaskCreatePinnedToCore(serverTask, "https443", 6144, NULL, 1, NULL, ARDUINO_RUNNING_CORE);

  pingPong();
}

void loop() {

  if (COM[0]!=NULL) {

    readPacket_();

    if(result==SUCCESSFUL_RX){
      
      // Send it back to every client
      msg.assign((char *)buf2, i2);
      for(int i = 0; i < MAX_CLIENTS; i++) {
        if (activeClients[i] != nullptr) {
          activeClients[i]->send(msg, 2);
        }
      }
      msg.clear();
      msg.shrink_to_fit();
            
      i2=0;
    }
  }
} 


void serverTask(void *params) {
  // In the separate task we first do everything that we would have done in the
  // setup() function, if we would run the server synchronously.

  // Note: The second task has its own stack, so you need to think about where
  // you create the server's resources and how to make sure that the server
  // can access everything it needs to access. Also make sure that concurrent
  // access is no problem in your sketch or implement countermeasures like locks
  // or mutexes.

  // Create nodes
  ResourceNode * nodeRoot    = new ResourceNode("/", "GET", &handleRoot);
  ResourceNode * node404     = new ResourceNode("", "GET", &handle404);
  ResourceNode * nodeInternal = new ResourceNode("/internal", "GET", &handleInternalPage);

  // Add nodes to the server
  secureServer.registerNode(nodeRoot);
  secureServer.setDefaultNode(node404);
  secureServer.registerNode(nodeInternal);

  WebsocketNode * chatNode = new WebsocketNode("/chat", &ChatHandler::create);

  // Adding the node to the server works in the same way as for all other nodes
  secureServer.registerNode(chatNode);

  secureServer.addMiddleware(&middlewareAuthentication);
  secureServer.addMiddleware(&middlewareAuthorization);

  Serial.println("Starting server...");
  secureServer.start();
  if (secureServer.isRunning()) {
    Serial.println("Server ready.");

    // "loop()" function of the separate task
    while(true) {
      // This call will let the server do its work
      secureServer.loop();

      // Other code would go here...
      delay(1);
    }
  }
}

WebsocketHandler * ChatHandler::create() {
  Serial.println("Creating new chat client!");
  ChatHandler * handler = new ChatHandler();
  for(int i = 0; i < MAX_CLIENTS; i++) {
    if (activeClients[i] == nullptr) {
      activeClients[i] = handler;
      break;
    }
  }
  return handler;
}

// When the websocket is closing, we remove the client from the array
void ChatHandler::onClose() {
  for(int i = 0; i < MAX_CLIENTS; i++) {
    if (activeClients[i] == this) {
      activeClients[i] = nullptr;
    }
  }
}

// Finally, passing messages around. If we receive something, we send it to all
// other clients
void ChatHandler::onMessage(WebsocketInputStreambuf * inbuf) {
  // Get the input message
  ss << std::hex << MYADDRESS;
  ss << " : ";
  ss << inbuf;

  msg.assign(ss.str());

  strcpy((char *)buf1, msg.c_str());
  for(int i=0; i<msg.length(); i++){
    Serial.printf("%x ", buf1[i]);
  }
  sendPacket_(SENDADDRESS, buf1, msg.length());

  // Send it back to every client
  for(int i = 0; i < MAX_CLIENTS; i++) {
    if (activeClients[i] != nullptr) {
      activeClients[i]->send(msg, SEND_TYPE_TEXT);
    }
  }
  ss.str("");
  ss.clear();
}

void handleRoot(HTTPRequest * req, HTTPResponse * res) {
  res->setHeader("Content-Type", "text/html");
  res->println("<!DOCTYPE html>");
  res->println("<html>");
  res->println("<head><title>Hello World!</title></head>");
  res->println("<body>");
  res->println("<h1>Hello World!</h1>");
  res->println("<p>This is the authentication and authorization example. When asked for login "
      "information, try admin/secret or user/test.</p>");
  res->println("<p>Go to: <a href=\"https://192.168.4.254/internal\">Internal Page</a>");
  res->println("</body>");
  res->println("</html>");
}

void handle404(HTTPRequest * req, HTTPResponse * res) {
  // Discard request body, if we received any
  // We do this, as this is the default node and may also server POST/PUT requests
  req->discardRequestBody();

  // Set the response status
  res->setStatusCode(404);
  res->setStatusText("Not Found");

  // Set content type of the response
  res->setHeader("Content-Type", "text/html");

  // Write a tiny HTTP page
  res->println("<!DOCTYPE html>");
  res->println("<html>");
  res->println("<head><title>Not Found</title></head>");
  res->println("<body><h1>404 Not Found</h1><p>The requested resource was not found on this server.</p></body>");
  res->println("</html>");
}

void middlewareAuthentication(HTTPRequest * req, HTTPResponse * res, std::function<void()> next) {
  // Unset both headers to discard any value from the client
  // This prevents authentication bypass by a client that just sets X-USERNAME
  req->setHeader(HEADER_USERNAME, "");
  req->setHeader(HEADER_GROUP, "");

  // Get login information from request
  // If you use HTTP Basic Auth, you can retrieve the values from the request.
  // The return values will be empty strings if the user did not provide any data,
  // or if the format of the Authorization header is invalid (eg. no Basic Method
  // for Authorization, or an invalid Base64 token)
  std::string reqUsername = req->getBasicAuthUser();
  std::string reqPassword = req->getBasicAuthPassword();

  // If the user entered login information, we will check it
  if (reqUsername.length() > 0 && reqPassword.length() > 0) {

    // _Very_ simple hardcoded user database to check credentials and assign the group
    bool authValid = true;
    std::string group = "";
    
    if (reqUsername == "user" && reqPassword == "test") {
      group = "USER";
    } else {
      authValid = false;
    }

    // If authentication was successful
    if (authValid) {
      // set custom headers and delegate control
      req->setHeader(HEADER_USERNAME, reqUsername);
      req->setHeader(HEADER_GROUP, group);

      // The user tried to authenticate and was successful
      // -> We proceed with this request.
      next();
    } else {
      // Display error page
      res->setStatusCode(401);
      res->setStatusText("Unauthorized");
      res->setHeader("Content-Type", "text/plain");

      // This should trigger the browser user/password dialog, and it will tell
      // the client how it can authenticate
      res->setHeader("WWW-Authenticate", "Basic realm=\"ESP32 privileged area\"");

      // Small error text on the response document. In a real-world scenario, you
      // shouldn't display the login information on this page, of course ;-)
      res->println("401. Unauthorized (try admin/secret or user/test)");

      // NO CALL TO next() here, as the authentication failed.
      // -> The code above did handle the request already.
    }
  } else {
    // No attempt to authenticate
    // -> Let the request pass through by calling next()
    next();
  }
}

void handleInternalPage(HTTPRequest * req, HTTPResponse * res) {
  // Header
  res->setStatusCode(200);
  res->setStatusText("OK");
  res->setHeader("Content-Type", "text/html; charset=utf8");

res->print(
    "<!DOCTYPE HTML>\n"
    "<html>\n"
    "   <head>\n"
    "   <title>ESP32 Chat</title>\n"
    "</head>\n"
    "<body>\n"
    "    <div style=\"width:500px;border:1px solid black;margin:20px auto;display:block\">\n"
    "        <form onsubmit=\"return false\">\n"
    "            Your Name: <input type=\"text\" id=\"txtName\" value=\"ESP32 user\">\n"
    "            <button type=\"submit\" id=\"btnConnect\">Connect</button>\n"
    "        </form>\n"
    "        <form onsubmit=\"return false\">\n"
    "            <div style=\"overflow:scroll;height:400px\" id=\"divOut\">Not connected...</div>\n"
    "            Your Message: <input type=\"text\" id=\"txtChat\" disabled>\n"
    "            <button type=\"submit\" id=\"btnSend\" disabled>Send</button>\n"
    "        </form>\n"
    "    </div>\n"
    "    <script type=\"text/javascript\">\n"
    "        const elem = id => document.getElementById(id);\n"
    "        const txtName = elem(\"txtName\");\n"
    "        const txtChat = elem(\"txtChat\");\n"
    "        const btnConnect = elem(\"btnConnect\");\n"
    "        const btnSend = elem(\"btnSend\");\n"
    "        const divOut = elem(\"divOut\");\n"
    "\n"
    "        class Chat {\n"
    "            constructor() {\n"
    "                this.connecting = false;\n"
    "                this.connected = false;\n"
    "                this.name = \"\";\n"
    "                this.ws = null;\n"
    "            }\n"
    "            connect() {\n"
    "                if (this.ws === null) {\n"
    "                    this.connecting = true;\n"
    "                    txtName.disabled = true;\n"
    "                    this.name = txtName.value;\n"
    "                    btnConnect.innerHTML = \"Connecting...\";\n"
    "                    this.ws = new WebSocket(\"wss://\" + document.location.host + \"/chat\");\n"
    "                    this.ws.onopen = e => {\n"
    "                        this.connecting = false;\n"
    "                        this.connected = true;\n"
    "                        divOut.innerHTML = \"<p>Connected.</p>\";\n"
    "                        btnConnect.innerHTML = \"Disconnect\";\n"
    "                        txtChat.disabled=false;\n"
    "                        btnSend.disabled=false;\n"
    "                        this.ws.send(this.name + \" joined!\");\n"
    "                    };\n"
    "                    this.ws.onmessage = e => {\n"
    "                        divOut.innerHTML+=\"<p>\"+e.data+\"</p>\";\n"
    "                        divOut.scrollTo(0,divOut.scrollHeight);\n"
    "                    }\n"
    "                    this.ws.onclose = e => {\n"
    "                        this.disconnect();\n"
    "                    }\n"
    "                }\n"
    "            }\n"
    "            disconnect() {\n"
    "                if (this.ws !== null) {\n"
    "                    this.ws.send(this.name + \" left!\");\n"
    "                    this.ws.close();\n"
    "                    this.ws = null;\n"
    "                }\n"
    "                if (this.connected) {\n"
    "                    this.connected = false;\n"
    "                    txtChat.disabled=true;\n"
    "                    btnSend.disabled=true;\n"
    "                    txtName.disabled = false;\n"
    "                    divOut.innerHTML+=\"<p>Disconnected.</p>\";\n"
    "                    btnConnect.innerHTML = \"Connect\";\n"
    "                }\n"
    "            }\n"
    "            sendMessage(msg) {\n"
    "                if (this.ws !== null) {\n"
    "                    this.ws.send(this.name + \": \" + msg);\n"
    "                }\n"
    "            }\n"
    "        };\n"
    "        let chat = new Chat();\n"
    "        btnConnect.onclick = () => {\n"
    "            if (chat.connected) {\n"
    "                chat.disconnect();\n"
    "            } else if (!chat.connected && !chat.connecting) {\n"
    "                chat.connect();\n"
    "            }\n"
    "        }\n"
    "        btnSend.onclick = () => {\n"
    "            chat.sendMessage(txtChat.value);\n"
    "            txtChat.value=\"\";\n"
    "            txtChat.focus();\n"
    "        }\n"
    "    </script>\n"
    "</body>\n"
    "</html>\n"
  );
}

/**
 * This function plays together with the middlewareAuthentication(). While the first function checks the
 * username/password combination and stores it in the request, this function makes use of this information
 * to allow or deny access.
 *
 * This example only prevents unauthorized access to every ResourceNode stored under an /internal/... path.
 */
void middlewareAuthorization(HTTPRequest * req, HTTPResponse * res, std::function<void()> next) {
  // Get the username (if any)
  std::string username = req->getHeader(HEADER_USERNAME);

  // Check that only logged-in users may get to the internal area (All URLs starting with /internal)
  // Only a simple example, more complicated configuration is up to you.
  if (username == "" && req->getRequestString().substr(0,9) == "/internal") {
    // Same as the deny-part in middlewareAuthentication()
    res->setStatusCode(401);
    res->setStatusText("Unauthorized");
    res->setHeader("Content-Type", "text/plain");
    res->setHeader("WWW-Authenticate", "Basic realm=\"ESP32 privileged area\"");
    res->println("401. Unauthorized (try admin/secret or user/test)");

    // No call denies access to protected handler function.
  } else {
    // Everything else will be allowed, so we call next()
    next();
  }
}


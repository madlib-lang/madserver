#include "App.h"
#include "Loop.h"
#include "HttpResponse.h"
#include "WebSocket.h"

#include "event-loop.hpp"
#include "gc.h"
#include "record.hpp"
#include <thread>
#include "uv.h"
#include "apply-pap.hpp"
#include "http.hpp"
#include "list.hpp"
#include "record.hpp"
#include "maybe.hpp"
#include "bytearray.hpp"



template<bool SSL> void madserver__handleResponse(uWS::HttpResponse<SSL> *res, madlib__record__Record_t *response) {
  madlib__bytearray__ByteArray_t *body = (madlib__bytearray__ByteArray_t*) response->fields[0]->value;

  int64_t status = (int64_t) response->fields[2]->value;
  madlib__list__Node_t *headers = (madlib__list__Node_t*) response->fields[1]->value;

  res->writeStatus(std::to_string(status));

  while (headers->value) {
    madlib__http__Header_t *header = (madlib__http__Header_t*) headers->value;
    res->writeHeader((char*) header->name, (char*) header->value);

    headers = headers->next;
  }

  res->end(std::string_view((const char*) body->bytes, body->length));
}


template<bool SSL> void madserver__requestHandler(PAP_t *handler, uWS::HttpResponse<SSL> *res, uWS::HttpRequest *req) {
  std::string bodyString;

  madlib__list__Node_t *headers = madlib__list__empty();
  auto headerIt = req->begin();
  while (headerIt != req->end()) {
    std::string_view headerName = (*headerIt).first;
    std::string_view headerValue = (*headerIt).second;

    madlib__http__Header_t *header = (madlib__http__Header_t*) GC_MALLOC(sizeof(madlib__http__Header_t));
    header->index = 0;
    header->name = (char*) GC_MALLOC_ATOMIC(headerName.size() + 1);
    memcpy(header->name, headerName.data(), headerName.size());
    header->name[headerName.size()] = '\0';

    header->value = (char*) GC_MALLOC_ATOMIC(headerValue.size() + 1);
    memcpy(header->value, headerValue.data(), headerValue.size());
    header->value[headerValue.size()] = '\0';

    headers = madlib__list__push(header, headers);

    ++headerIt;
  }

  madlib__http__Method_t *method = (madlib__http__Method_t*) GC_MALLOC(sizeof(madlib__http__Method_t));
  if (req->getMethod() == "get") {
      method->methodIndex = 2;
  } else if (req->getMethod() == "post") {
      method->methodIndex = 6;
  } else if (req->getMethod() == "put") {
      method->methodIndex = 7;
  } else if (req->getMethod() == "patch") {
      method->methodIndex = 5;
  } else if (req->getMethod() == "delete") {
      method->methodIndex = 1;
  } else if (req->getMethod() == "head") {
      method->methodIndex = 3;
  } else if (req->getMethod() == "connect") {
      method->methodIndex = 0;
  } else if (req->getMethod() == "trace") {
      method->methodIndex = 8;
  } else if (req->getMethod() == "options") {
      method->methodIndex = 4;
  } else {
    // we default to GET if we don't know
    method->methodIndex = 2;
  }

  char *path;
  if (!req->getQuery().empty()) {
    path = (char *) GC_MALLOC_ATOMIC(req->getUrl().size() + req->getQuery().size() + 2);
    memcpy(path, req->getUrl().data(), req->getUrl().size());
    path[req->getUrl().size()] = '?';
    memcpy(path + req->getUrl().size() + 1, req->getQuery().data(), req->getQuery().size());
    path[req->getUrl().size() + req->getQuery().size() + 1] = '\0';
  } else {
    path = (char *) GC_MALLOC_ATOMIC(req->getUrl().size() + 1);
    memcpy(path, req->getUrl().data(), req->getUrl().size());
    path[req->getUrl().size()] = '\0';
  }

  res->onData([handler, res, bodyString = std::move(bodyString), headers, path, method](std::string_view data, bool last) mutable {
    bodyString.append(data.data(), data.length());

    if (last) {
      // build body:
      madlib__bytearray__ByteArray_t *body = (madlib__bytearray__ByteArray_t*) GC_MALLOC(sizeof(madlib__bytearray__ByteArray_t));
      if (bodyString.empty()) {
        body->length = 0;
      } else {
        body->length = bodyString.length();
        unsigned char *bodyCopy = (unsigned char*) GC_MALLOC_ATOMIC(bodyString.length() + 1);
        memcpy(bodyCopy, bodyString.c_str(), bodyString.length());
        bodyCopy[bodyString.length()] = '\0';
        body->bytes = bodyCopy;
      }

      // ip address, most likely v6
      std::string_view remoteIp = res->getRemoteAddressAsText();
      char *ip = (char*) GC_MALLOC_ATOMIC(remoteIp.size() + 1);
      memcpy(ip, remoteIp.data(), remoteIp.size());
      ip[remoteIp.size()] = '\0';

      madlib__record__Record_t *request = (madlib__record__Record_t*) GC_MALLOC(sizeof(madlib__record__Record_t));

      madlib__record__Field_t *pathField = (madlib__record__Field_t*) GC_MALLOC(sizeof(madlib__record__Field_t));
      pathField->name = (char*) "path";
      pathField->value = path;

      madlib__record__Field_t *methodField = (madlib__record__Field_t*) GC_MALLOC(sizeof(madlib__record__Field_t));
      methodField->name = (char*) "method";
      methodField->value = method;

      madlib__record__Field_t *bodyField = (madlib__record__Field_t*) GC_MALLOC(sizeof(madlib__record__Field_t));
      bodyField->name = (char*) "body";
      bodyField->value = body;

      madlib__record__Field_t *headersField = (madlib__record__Field_t*) GC_MALLOC(sizeof(madlib__record__Field_t));
      headersField->name = (char*) "headers";
      headersField->value = headers;

      madlib__record__Field_t *ipField = (madlib__record__Field_t*) GC_MALLOC(sizeof(madlib__record__Field_t));
      ipField->name = (char*) "ip";
      ipField->value = (void*) ip;

      madlib__record__Field_t *queryParametersField = (madlib__record__Field_t*) GC_MALLOC(sizeof(madlib__record__Field_t));
      queryParametersField->name = (char*) "queryParameters";
      // NULL is fine as this is overriden by the addRoute function
      queryParametersField->value = NULL;

      madlib__record__Field_t *urlParametersField = (madlib__record__Field_t*) GC_MALLOC(sizeof(madlib__record__Field_t));
      urlParametersField->name = (char*) "urlParameters";
      // NULL is fine as this is overriden by the addRoute function
      urlParametersField->value = NULL;

      madlib__record__Field_t **requestFields = (madlib__record__Field_t**) GC_MALLOC(sizeof(madlib__record__Field_t*) * 7);
      requestFields[0] = bodyField;
      requestFields[1] = headersField;
      requestFields[2] = ipField;
      requestFields[3] = methodField;
      requestFields[4] = pathField;
      requestFields[5] = queryParametersField;
      requestFields[6] = urlParametersField;

      request->fieldCount = 7;
      request->fields = requestFields;

      PAP_t *callback = (PAP_t*) GC_MALLOC(sizeof(PAP_t));
      callback->fn = (void*) madserver__handleResponse<SSL>;
      callback->arity = 2;
      callback->missingArgCount = 1;

      PAPEnv_2_t *env = (PAPEnv_2_t*) GC_MALLOC(sizeof(PAPEnv_2_t));
      env->arg0 = res;
      callback->env = env;

      __applyPAP__(handler, 2, request, callback);
    }
  });

  res->onAborted([]() {
    std::cout << "aborted" << std::endl;
  });
}

#ifdef __cplusplus
extern "C" {
#endif


  typedef struct madserver__server {
    madlib__record__Record_t *options;
    void *uWSApp;
  } madserver__server_t;


  typedef struct madserver__socket {
    bool isSSL;
    void *uWSSocket;
  } madserver__socket_t;


  bool isSSL(madserver__server_t *server) {
    madlib__maybe__Maybe_t *sslOptions = (madlib__maybe__Maybe_t*) madlib__record__internal__selectField((char*) "ssl", server->options);
    return sslOptions->index == 0;
  }


  madlib__record__Record_t *madserver__getOptions(madserver__server_t *server) {
    return server->options;
  }


  madserver__server_t *madserver__create(madlib__record__Record_t *options) {
    uWS::Loop::get(getLoop());

    // TODO: use GC_MALLOC for server and use a finalizer to delete the uWS::App it contains
    madserver__server_t *server = (madserver__server_t*) GC_MALLOC_UNCOLLECTABLE(sizeof(madserver__server_t));
    server->options = options;

    madlib__maybe__Maybe_t *sslOptions = (madlib__maybe__Maybe_t*) madlib__record__internal__selectField((char*) "ssl", options);
    if (sslOptions->index == madlib__maybe__Maybe_NOTHING_INDEX) {
      server->uWSApp = (void*) new uWS::App;
    } else {
      madlib__record__Record_t *sslOptionsRecord = (madlib__record__Record_t *) sslOptions->data;
      char *certificateFile = (char*) madlib__record__internal__selectField((char*) "certificateFile", sslOptionsRecord);
      char *keyFile = (char*) madlib__record__internal__selectField((char*) "keyFile", sslOptionsRecord);
      madlib__maybe__Maybe_t *maybePassphrase = (madlib__maybe__Maybe_t*) madlib__record__internal__selectField((char*) "passphrase", sslOptionsRecord);
      madlib__maybe__Maybe_t *maybeCaFile = (madlib__maybe__Maybe_t*) madlib__record__internal__selectField((char*) "caFile", sslOptionsRecord);

      char *passphrase = (char*) (
        maybePassphrase->index == madlib__maybe__Maybe_NOTHING_INDEX
          ? NULL
          : maybePassphrase->data
      );

      char *caFile = (char*) (
        maybeCaFile->index == madlib__maybe__Maybe_NOTHING_INDEX
          ? NULL
          : maybeCaFile->data
      );

      server->uWSApp = (void*) new uWS::SSLApp({
        .key_file_name = keyFile,
        .cert_file_name = certificateFile,
        .passphrase = passphrase,
        .dh_params_file_name = NULL,
        .ca_file_name = caFile
      });
    }

    return server;
  }

  madserver__server_t *madserver__run(int64_t port, madserver__server_t *server) {
    if (isSSL(server)) {
      uWS::SSLApp *app = (uWS::SSLApp*)server->uWSApp;
      app->listen(port, [port](auto *listenSocket) {
        if (!listenSocket) {
          std::cout << "failed to listen" << std::endl;
          // TODO: handle error case, return an Either?
        }
      });
      app->run();
      return server;
    } else {
      uWS::App *app = (uWS::App*)server->uWSApp;
      app->listen(port, [port](auto *listenSocket) {
        if (!listenSocket) {
          std::cout << "failed to listen" << std::endl;
          // TODO: handle error case, return an Either?
        }
      });
      app->run();
      return server;
    }
  }

  int64_t madserver__getSocketIdFFI(madserver__socket_t *madSocket) {
    if (madSocket->isSSL) {
      return (int64_t) ((uWS::WebSocket<true, true, void*>*) madSocket->uWSSocket)->getNativeHandle();
    } else {
      return (int64_t) ((uWS::WebSocket<false, true, void*>*) madSocket->uWSSocket)->getNativeHandle();
    }
  }

  madserver__server_t *madserver__addWebSocketHandler(char *path, madlib__record__Record_t *handler, madserver__server_t *server) {
    auto open = [handler, server](auto *ws) {
      madserver__socket_t* socket = (madserver__socket_t*) GC_MALLOC(sizeof(madserver__socket_t));
      socket->uWSSocket = ws;
      socket->isSSL = isSSL(server);
      __applyPAP__(handler->fields[0]->value, 1, (void*)socket);
    };

    auto message = [handler, server](auto *ws, std::string_view message, uWS::OpCode opCode) {
      madserver__socket_t* socket = (madserver__socket_t*) GC_MALLOC(sizeof(madserver__socket_t));
      socket->uWSSocket = ws;
      socket->isSSL = isSSL(server);

      if (opCode == uWS::BINARY) {
        madlib__bytearray__ByteArray_t *msg = (madlib__bytearray__ByteArray_t*) GC_MALLOC(sizeof(madlib__bytearray__ByteArray_t));
        msg->length = message.length();
        unsigned char *messageBytes = (unsigned char*) GC_MALLOC_ATOMIC(message.length());
        memcpy(messageBytes, message.data(), message.length());
        msg->bytes = messageBytes;

        __applyPAP__(handler->fields[2]->value, 2, (void*)socket, msg);
      } else if (opCode == uWS::TEXT) {
        madlib__bytearray__ByteArray_t *msg = (madlib__bytearray__ByteArray_t*) GC_MALLOC(sizeof(madlib__bytearray__ByteArray_t));
        msg->length = message.length();
        unsigned char *messageBytes = (unsigned char*) GC_MALLOC_ATOMIC(message.length() + 1);
        memcpy(messageBytes, message.data(), message.length());
        messageBytes[message.length()] = '\0';
        msg->bytes = messageBytes;

        __applyPAP__(handler->fields[2]->value, 2, (void*)socket, msg);
      }
    };

    if (isSSL(server)) {
      ((uWS::SSLApp*)server->uWSApp)->ws<void*>(std::string(path), {
        .open = open,
        .message = message,
      });
    } else {
      ((uWS::App*)server->uWSApp)->ws<void*>(std::string(path), {
        .open = open,
        .message = message,
      });
    }

    return server;
  }

  void madserver__sendFFI(madlib__bytearray__ByteArray_t *data, madserver__socket_t *madSocket) {
    if (madSocket->isSSL) {
      ((uWS::WebSocket<true, true, void*>*) madSocket->uWSSocket)->send(std::string_view((const char*) data->bytes, data->length));
    } else {
      ((uWS::WebSocket<false, true, void*>*) madSocket->uWSSocket)->send(std::string_view((const char*) data->bytes, data->length));
    }
  }

  madserver__server_t *madserver__addGetHandler(char *path, PAP_t *handler, madserver__server_t *server) {
    if (isSSL(server)) {
      ((uWS::SSLApp*)server->uWSApp)->get(std::string(path), [handler](auto *res, auto *req) {
        madserver__requestHandler(handler, res, req);
      });
    } else {
      ((uWS::App*)server->uWSApp)->get(std::string(path), [handler](auto *res, auto *req) {
        madserver__requestHandler(handler, res, req);
      });
    }

    return server;
  }

  madserver__server_t *madserver__addPostHandler(char *path, PAP_t *handler, madserver__server_t *server) {
   if (isSSL(server)) {
      ((uWS::SSLApp*)server->uWSApp)->post(std::string(path), [handler](auto *res, auto *req) {
        madserver__requestHandler(handler, res, req);
      });
    } else {
      ((uWS::App*)server->uWSApp)->post(std::string(path), [handler](auto *res, auto *req) {
        madserver__requestHandler(handler, res, req);
      });
    }

    return server;
  }

  madserver__server_t *madserver__addPutHandler(char *path, PAP_t *handler, madserver__server_t *server) {
    if (isSSL(server)) {
      ((uWS::SSLApp*)server->uWSApp)->put(std::string(path), [handler](auto *res, auto *req) {
        madserver__requestHandler(handler, res, req);
      });
    } else {
      ((uWS::App*)server->uWSApp)->put(std::string(path), [handler](auto *res, auto *req) {
        madserver__requestHandler(handler, res, req);
      });
    }

    return server;
  }

  madserver__server_t *madserver__addPatchHandler(char *path, PAP_t *handler, madserver__server_t *server) {
    if (isSSL(server)) {
      ((uWS::SSLApp*)server->uWSApp)->patch(std::string(path), [handler](auto *res, auto *req) {
        madserver__requestHandler(handler, res, req);
      });
    } else {
      ((uWS::App*)server->uWSApp)->patch(std::string(path), [handler](auto *res, auto *req) {
        madserver__requestHandler(handler, res, req);
      });
    }

    return server;
  }

  madserver__server_t *madserver__addDeleteHandler(char *path, PAP_t *handler, madserver__server_t *server) {
    if (isSSL(server)) {
      ((uWS::SSLApp*)server->uWSApp)->del(std::string(path), [handler](auto *res, auto *req) {
        madserver__requestHandler(handler, res, req);
      });
    } else {
      ((uWS::App*)server->uWSApp)->del(std::string(path), [handler](auto *res, auto *req) {
        madserver__requestHandler(handler, res, req);
      });
    }

    return server;
  }

  madserver__server_t *madserver__addHeadHandler(char *path, PAP_t *handler, madserver__server_t *server) {
    if (isSSL(server)) {
      ((uWS::SSLApp*)server->uWSApp)->head(std::string(path), [handler](auto *res, auto *req) {
        madserver__requestHandler(handler, res, req);
      });
    } else {
      ((uWS::App*)server->uWSApp)->head(std::string(path), [handler](auto *res, auto *req) {
        madserver__requestHandler(handler, res, req);
      });
    }

    return server;
  }

  madserver__server_t *madserver__addConnectHandler(char *path, PAP_t *handler, madserver__server_t *server) {
    if (isSSL(server)) {
      ((uWS::SSLApp*)server->uWSApp)->connect(std::string(path), [handler](auto *res, auto *req) {
        madserver__requestHandler(handler, res, req);
      });
    } else {
      ((uWS::App*)server->uWSApp)->connect(std::string(path), [handler](auto *res, auto *req) {
        madserver__requestHandler(handler, res, req);
      });
    }

    return server;
  }

  madserver__server_t *madserver__addTraceHandler(char *path, PAP_t *handler, madserver__server_t *server) {
    if (isSSL(server)) {
      ((uWS::SSLApp*)server->uWSApp)->trace(std::string(path), [handler](auto *res, auto *req) {
        madserver__requestHandler(handler, res, req);
      });
    } else {
      ((uWS::App*)server->uWSApp)->trace(std::string(path), [handler](auto *res, auto *req) {
        madserver__requestHandler(handler, res, req);
      });
    }

    return server;
  }

  madserver__server_t *madserver__addOptionsHandler(char *path, PAP_t *handler, madserver__server_t *server) {
    if (isSSL(server)) {
      ((uWS::SSLApp*)server->uWSApp)->options(std::string(path), [handler](auto *res, auto *req) {
        madserver__requestHandler(handler, res, req);
      });
    } else {
      ((uWS::App*)server->uWSApp)->options(std::string(path), [handler](auto *res, auto *req) {
        madserver__requestHandler(handler, res, req);
      });
    }

    return server;
  }

  madserver__server_t *madserver__addAnyHandler(char *path, PAP_t *handler, madserver__server_t *server) {
    if (isSSL(server)) {
      ((uWS::SSLApp*)server->uWSApp)->any(std::string(path), [handler](auto *res, auto *req) {
        madserver__requestHandler(handler, res, req);
      });
    } else {
      ((uWS::App*)server->uWSApp)->any(std::string(path), [handler](auto *res, auto *req) {
        madserver__requestHandler(handler, res, req);
      });
    }

    return server;
  }

#ifdef __cplusplus
}
#endif

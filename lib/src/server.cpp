#include "App.h"
#include "Loop.h"
#include "HttpResponse.h"

#include "event-loop.hpp"
#include "gc.h"
#include "record.hpp"
#include <thread>
#include "uv.h"
#include "apply-pap.hpp"
#include "http.hpp"
#include "list.hpp"
#include "record.hpp"



template<bool SSL> void madserver__handleResponse(uWS::HttpResponse<SSL> *res, madlib__record__Record_t *response) {
  char *body = (char*) madlib__record__internal__selectField((char*) "body", response);
  int64_t status = (int64_t) madlib__record__internal__selectField((char*) "status", response);
  madlib__list__Node_t *headers = (madlib__list__Node_t*) madlib__record__internal__selectField((char*) "headers", response);

  res->writeStatus(std::to_string(status));

  while (headers->value) {
    madlib__http__Header_t *header = (madlib__http__Header_t*) headers->value;
    res->writeHeader((char*) header->name, (char*) header->value);

    headers = headers->next;
  }

  res->end(body);
}


template<bool SSL> void madserver__requestHandler(PAP_t *handler, uWS::HttpResponse<SSL> *res, uWS::HttpRequest *req) {
  std::string bodyString;
  res->onData([handler, res, req, bodyString = std::move(bodyString)](std::string_view data, bool last) mutable {
    bodyString.append(data.data(), data.length());

    if (last) {
      // build body:
      madlib__http__Body_t *body = (madlib__http__Body_t*) GC_MALLOC(sizeof(madlib__http__Body_t));
      if (bodyString.empty()) {
        body->index = 1;
      } else {
        body->index = 0;
      }

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
      method->methodIndex = 2; // GET

      char *url;
      if (!req->getQuery().empty()) {
        url = (char *) GC_MALLOC_ATOMIC(req->getUrl().size() + req->getQuery().size() + 2);
        memcpy(url, req->getUrl().data(), req->getUrl().size());
        url[req->getUrl().size()] = '?';
        memcpy(url + req->getUrl().size() + 1, req->getQuery().data(), req->getQuery().size());
        url[req->getUrl().size() + req->getQuery().size() + 1] = '\0';
      } else {
        url = (char *) GC_MALLOC_ATOMIC(req->getUrl().size() + 1);
        memcpy(url, req->getUrl().data(), req->getUrl().size());
        url[req->getUrl().size()] = '\0';
      }

      madlib__record__Record_t *request = (madlib__record__Record_t*) GC_MALLOC(sizeof(madlib__record__Record_t));

      madlib__record__Field_t *urlField = (madlib__record__Field_t*) GC_MALLOC(sizeof(madlib__record__Field_t));
      urlField->name = (char*) "url";
      urlField->value = url;

      madlib__record__Field_t *methodField = (madlib__record__Field_t*) GC_MALLOC(sizeof(madlib__record__Field_t));
      methodField->name = (char*) "method";
      methodField->value = method;

      madlib__record__Field_t *bodyField = (madlib__record__Field_t*) GC_MALLOC(sizeof(madlib__record__Field_t));
      bodyField->name = (char*) "body";
      bodyField->value = body;

      madlib__record__Field_t *headersField = (madlib__record__Field_t*) GC_MALLOC(sizeof(madlib__record__Field_t));
      headersField->name = (char*) "headers";
      headersField->value = headers;

      madlib__record__Field_t **requestFields = (madlib__record__Field_t**) GC_MALLOC(sizeof(madlib__record__Field_t*) * 4);
      requestFields[0] = urlField;
      requestFields[1] = bodyField;
      requestFields[2] = methodField;
      requestFields[3] = headersField;

      request->fieldCount = 4;
      request->fields = requestFields;

      PAP_t *callback = (PAP_t*) GC_MALLOC(sizeof(PAP_t));
      callback->fn = (void*) madserver__handleResponse<true>;
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
    uWS::App *uWSApp;
  } madserver__server_t;


  madlib__record__Record_t *madserver__getOptions(madserver__server_t *server) {
    return server->options;
  }


  madserver__server_t *madserver__create(madlib__record__Record_t *options) {
    uWS::Loop::get(getLoop());

    // TODO: use GC_MALLOC for server and use a finalizer to delete the uWS::App it contains
    madserver__server_t *server = (madserver__server_t*) GC_MALLOC_UNCOLLECTABLE(sizeof(madserver__server_t));
    server->options = options;
    server->uWSApp = new uWS::App;
    return server;
  }

  madserver__server_t *madserver__run(int64_t port, madserver__server_t *server) {
    server->uWSApp->listen(port, [port](auto *listenSocket) {
      if (!listenSocket) {
        // TODO: handle error case, return an Either?
      }
    });
    server->uWSApp->run();
    return server;
  }

  madserver__server_t *madserver__addGetHandler(char *path, PAP_t *handler, madserver__server_t *server) {
    server->uWSApp->get(std::string(path), [handler](auto *res, auto *req) {
      madserver__requestHandler(handler, res, req);
    });

    return server;
  }

  madserver__server_t *madserver__addPostHandler(char *path, PAP_t *handler, madserver__server_t *server) {
    server->uWSApp->post(std::string(path), [handler](auto *res, auto *req) {
      madserver__requestHandler(handler, res, req);
    });

    return server;
  }

  madserver__server_t *madserver__addPutHandler(char *path, PAP_t *handler, madserver__server_t *server) {
    server->uWSApp->put(std::string(path), [handler](auto *res, auto *req) {
      madserver__requestHandler(handler, res, req);
    });

    return server;
  }

  madserver__server_t *madserver__addPatchHandler(char *path, PAP_t *handler, madserver__server_t *server) {
    server->uWSApp->patch(std::string(path), [handler](auto *res, auto *req) {
      madserver__requestHandler(handler, res, req);
    });

    return server;
  }

  madserver__server_t *madserver__addDeleteHandler(char *path, PAP_t *handler, madserver__server_t *server) {
    server->uWSApp->del(std::string(path), [handler](auto *res, auto *req) {
      madserver__requestHandler(handler, res, req);
    });

    return server;
  }

  madserver__server_t *madserver__addHeadHandler(char *path, PAP_t *handler, madserver__server_t *server) {
    server->uWSApp->head(std::string(path), [handler](auto *res, auto *req) {
      madserver__requestHandler(handler, res, req);
    });

    return server;
  }

  madserver__server_t *madserver__addConnectHandler(char *path, PAP_t *handler, madserver__server_t *server) {
    server->uWSApp->connect(std::string(path), [handler](auto *res, auto *req) {
      madserver__requestHandler(handler, res, req);
    });

    return server;
  }

  madserver__server_t *madserver__addTraceHandler(char *path, PAP_t *handler, madserver__server_t *server) {
    server->uWSApp->trace(std::string(path), [handler](auto *res, auto *req) {
      madserver__requestHandler(handler, res, req);
    });

    return server;
  }

  madserver__server_t *madserver__addOptionsHandler(char *path, PAP_t *handler, madserver__server_t *server) {
    server->uWSApp->options(std::string(path), [handler](auto *res, auto *req) {
      madserver__requestHandler(handler, res, req);
    });

    return server;
  }

  madserver__server_t *madserver__addAnyHandler(char *path, PAP_t *handler, madserver__server_t *server) {
    server->uWSApp->any(std::string(path), [handler](auto *res, auto *req) {
      madserver__requestHandler(handler, res, req);
    });

    return server;
  }

#ifdef __cplusplus
}
#endif


void startServer(void *_) {
  uWS::Loop::get(getLoop());
  uWS::App()
    .get("/hello", [](auto *res, auto *req) {
      /* You can efficiently stream huge files too */
      std::cout << "request" << std::endl;
      res->writeHeader("Content-Type", "text/html; charset=utf-8")->end("Hello HTTP!");
    })
    .any("/*", [](auto *res, auto *req) {
      /* You can efficiently stream huge files too */
      std::cout << "request" << std::endl;
      res->writeHeader("Content-Type", "text/html; charset=utf-8")->end("404");
    })
    .listen(9001, [](auto *listenSocket) {
      if (listenSocket) {
          std::cout << "Listening on port " << 9001 << std::endl;
      }
    }).run();
}

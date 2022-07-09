#include "App.h"
#include "Loop.h"
#include "event-loop.hpp"
#include "gc.h"
#include "record.hpp"
#include<thread>
#include "uv.h"


extern "C" {

  typedef struct madserver__server {
    madlib__record__Record_t *options;
    uWS::App *uWSApp;
  } madserver__server_t;


  madlib__record__Record_t *madserver__getOptions(madserver__server_t *server) {
    return server->options;
  }


  madserver__server_t *madserver__create(madlib__record__Record_t *options) {
    uWS::Loop::get(getLoop());
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

  // void madserver__run2(void *server) {
  //   int64_t port = 3000;
  //   ((madserver__server_t*) server)->uWSApp->listen(port, [port](auto *listenSocket) {
  //     if (!listenSocket) {
  //       // TODO: handle error case, return an Either?
  //     }
  //   });
  //   ((madserver__server_t*) server)->uWSApp->run();
  //   uv_barrier_wait(&blocker);
  // }

  // madserver__server_t *madserver__threaded_run(int64_t port, madserver__server_t *server) {
  //   uv_thread_t t_id;
  //   uv_barrier_init(&blocker, 2);
  //   uv_thread_create(&t_id, madserver__run2, server);
  //   uv_thread_detach(&t_id);
  //   uv_barrier_wait(&blocker);
  //   uv_barrier_destroy(&blocker);
  //   return server;
  // }

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

}

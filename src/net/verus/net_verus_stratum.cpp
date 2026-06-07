#include "../net.hpp"
#include <hex.h>

#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ip/host_name.hpp>
#include <boost/json.hpp>
#include <atomic>
#include <cstdlib>
#include <fstream>
#include "coins/verus_job_snapshot.hpp"

#include <stratum/stratum.h>
#include <spectrex/spectrex.h>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

static std::atomic<int> wave39UserSubmitCount{0};

static int wave39UserSubmitLimit() {
  const char *limit = std::getenv("TNN_WAVE39_MAX_USER_SUBMITS");
  if (!limit || !*limit) return -1;
  return std::atoi(limit);
}

static int wave41VerusReadTimeoutSeconds() {
  const char *timeout = std::getenv("TNN_WAVE41_VERUS_READ_TIMEOUT_SECONDS");
  int seconds = (timeout && *timeout) ? std::atoi(timeout) : 1800;
  return seconds > 0 ? seconds : 1800;
}

static int wave41VerusJobTimeoutSeconds() {
  const char *timeout = std::getenv("TNN_WAVE41_VERUS_JOB_TIMEOUT_SECONDS");
  int seconds = (timeout && *timeout) ? std::atoi(timeout) : 1800;
  return seconds > 0 ? seconds : 1800;
}

static uint64_t wave41NowSeconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(
    std::chrono::steady_clock::now().time_since_epoch()).count();
}

static void wave41TouchVerusJobClock() {
  SpectreStratum::lastReceivedJobTime = wave41NowSeconds();
}


static void wave37HandleVerusPacketForSnapshot(const boost::json::object &rpc,
                                               const std::string &workerName,
                                               std::string &target,
                                               const std::string &poolNonce) {
  const char *logPath = std::getenv("TNN_VERUS_WAVE37_DRYRUN_LOG");
  if (!rpc.if_contains("method")) return;
  std::string method = rpc.at("method").as_string().c_str();
  if (logPath && *logPath) {
    std::ofstream out(logPath, std::ios::app);
    out << "{\"event\":\"wave39_packet_seen\",\"method\":\"" << method << "\"";
    if (rpc.if_contains("params") && rpc.at("params").is_array()) {
      out << ",\"params_size\":" << rpc.at("params").as_array().size();
    }
    out << "}\n";
  }
  if (method == "mining.set_target" && rpc.if_contains("params") && rpc.at("params").is_array()) {
    auto params = rpc.at("params").as_array();
    if (!params.empty() && params[0].is_string()) {
      target = params[0].as_string().c_str();
      if (logPath && *logPath) {
        std::ofstream out(logPath, std::ios::app);
        out << "{\"event\":\"wave39_target_seen\",\"target_len\":" << target.size() << "}\n";
      }
    }
  } else if (method == "mining.notify") {
    Wave37VerusJobSnapshot snap;
    bool ok = false;
    try {
      ok = wave37SnapshotFromNotify(rpc, workerName, target, poolNonce, snap);
    } catch (const std::exception &e) {
      if (logPath && *logPath) {
        std::ofstream out(logPath, std::ios::app);
        out << "{\"event\":\"wave39_notify_exception\",\"what\":\"" << e.what() << "\"}\n";
      }
    }
    if (ok) {
      wave37StoreSnapshot(snap);
      wave37WriteSnapshotJsonl(logPath ? logPath : "", snap, "net_verus_notify_snapshot");
    } else if (logPath && *logPath) {
      std::ofstream out(logPath, std::ios::app);
      out << "{\"event\":\"wave39_notify_no_snapshot\",\"job_id_len\":" << snap.job_id.size()
          << ",\"ntime_len\":" << snap.ntime.size()
          << ",\"solution_len\":" << snap.solution.size()
          << ",\"target_len\":" << snap.target.size()
          << ",\"pool_nonce_len\":" << snap.pool_nonce.size()
          << "}\n";
    }
  }
}

// int handleVerusStratumPacket(boost::json::object packet, SpectreStratum::jobCache *cache, bool isDev)
// {
//   std::string M = packet.at("method").get_string().c_str();
//   // std::cout << "Stratum packet: " << boost::json::serialize(packet).c_str() << std::endl;
//   if (M.compare(SpectreStratum::s_notify) == 0)
//   {
//     std::scoped_lock<std::mutex> lockGuard(mutex);
//     boost::json::value *J = isDev ? &devJob : &job;
//     int64_t *h = isDev ? &devHeight : &ourHeight;

//     uint64_t h1 = packet["params"].as_array()[1].as_array()[0].get_uint64();
//     uint64_t h2 = packet["params"].as_array()[1].as_array()[1].get_uint64();
//     uint64_t h3 = packet["params"].as_array()[1].as_array()[2].get_uint64();
//     uint64_t h4 = packet["params"].as_array()[1].as_array()[3].get_uint64();

//     uint64_t comboHeader[4] = {h1, h2, h3, h4};

//     bool isEqual = true;
//     for (int i = 0; i < 4; i++) {
//       isEqual &= comboHeader[i] == cache->header[i];
//     }
//     if (isEqual) return 0;

//     for (int i = 0; i < 4; i++) {
//       cache->header[i] = comboHeader[i];
//     }

//     uint64_t ts = packet["params"].as_array()[2].get_uint64();

//     std::string h1Str = hexStr((byte*)&h1, 8);
//     std::string h2Str = hexStr((byte*)&h2, 8);
//     std::string h3Str = hexStr((byte*)&h3, 8);
//     std::string h4Str = hexStr((byte*)&h4, 8);

//     std::string tsStr = hexStr((byte*)&ts, 8);

//     char newTemplate[160];
//     memset(newTemplate, '0', 160);

//     memcpy(newTemplate + 16 - h1Str.size(), h1Str.data(), h1Str.size());
//     memcpy(newTemplate + 16 + 16 - h2Str.size(), h2Str.data(), h2Str.size());
//     memcpy(newTemplate + 32 + 16 - h3Str.size(), h3Str.data(), h3Str.size());
//     memcpy(newTemplate + 48 + 16 - h4Str.size(), h4Str.data(), h4Str.size());
//     memcpy(newTemplate + 64 + 16 - tsStr.size(), tsStr.data(), tsStr.size());

//     if(!beQuiet) {
//       setcolor(CYAN);
//       if (!isDev)
//         printf("\nStratum: new job received\n");
//       fflush(stdout);
//       setcolor(BRIGHT_WHITE);
//     }

//     SpectreStratum::lastReceivedJobTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count();


//     (*J).as_object()["template"] = std::string(newTemplate, SpectreX::INPUT_SIZE*2);
//     (*J).as_object()["jobId"] = packet["params"].as_array()[0].get_string().c_str();

//     bool *C = isDev ? &devConnected : &isConnected;
//     if (!*C)
//     {
//       if (!isDev)
//       {
//         setcolor(BRIGHT_YELLOW);
//         printf("Mining at: %s to wallet %s\n", host.c_str(), wallet.c_str());
//         fflush(stdout);
//         setcolor(CYAN);
//         printf("Dev fee: %.2f%% of your total hashrate\n", devFee);

//         fflush(stdout);
//         setcolor(BRIGHT_WHITE);
//       }
//       else
//       {
//         setcolor(CYAN);
//         printf("Connected to dev node: %s\n", host.c_str());
//         fflush(stdout);
//         setcolor(BRIGHT_WHITE);
//       }
//     }

//     *C = true;
//     (*h)++;
//     jobCounter++;
//   }
//   else if (M.compare(SpectreStratum::s_setDifficulty) == 0)
//   {
//     // std::cout << boost::json::serialize(packet).c_str() << std::endl;
//     double *d = isDev ? &doubleDiffDev : &doubleDiff;
//     (*d) = packet.at("params").as_array()[0].get_double();
//     if ((*d) < 0.00000000001) (*d) = packet.at("params").as_array()[0].get_uint64();

//     // printf("%f\n", (*d));
//   }
//   else if (M.compare(SpectreStratum::s_setExtraNonce) == 0)
//   {
//     std::scoped_lock<std::mutex> lockGuard(mutex);
//     boost::json::value *J = isDev ? &devJob : &job;
//     // uint64_t *h = isDev ? &devHeight : &ourHeight;

//     // std::string bs = (*J).at("template").get<std::string>();
//     // char *blob = (char *)bs.c_str();
//     const char *en = packet.at("params").as_array()[0].as_string().c_str();
//     // char *c = NULL;
//     int enLen = packet.at("params").as_array()[0].as_string().size();

//     // uint32_t EN = strtoul(en, &c, 16);


//     // memset(&blob[48], '0', 64);
//     // memcpy(&blob[48], en, enLen);

//     (*J).as_object()["extraNonce"] = std::string(en);

//     // (*h)++;
//     // jobCounter++;
//   }
//   else if (M.compare(SpectreStratum::s_print) == 0)
//   {

//     int lLevel = packet.at("params").as_array()[0].to_number<int64_t>();
//     if (lLevel != SpectreStratum::STRATUM_DEBUG)
//     {
//       int res = 0;
//       printf("\n");
//       if (isDev)
//       {
//         setcolor(CYAN);
//         printf("DEV | ");
//       }

//       switch (lLevel)
//       {
//       case SpectreStratum::STRATUM_INFO:
//         if (!isDev)
//           setcolor(BRIGHT_WHITE);
//         printf("Stratum INFO: ");
//         break;
//       case SpectreStratum::STRATUM_WARN:
//         if (!isDev)
//           setcolor(BRIGHT_YELLOW);
//         printf("Stratum WARNING: ");
//         break;
//       case SpectreStratum::STRATUM_ERROR:
//         if (!isDev)
//           setcolor(RED);
//         printf("Stratum ERROR: ");
//         res = -1;
//         break;
//       case SpectreStratum::STRATUM_DEBUG:
//         break;
//       }
//       printf("%s\n", packet.at("params").as_array()[1].as_string().c_str());

//       fflush(stdout);
//       setcolor(BRIGHT_WHITE);
//       return res;
//     }
//   } else {
//     std::cout << "Stratum: unrecognized packet: " << boost::json::serialize(packet).c_str() << std::endl;
//   }
//   return 0;
// }

// int handleVerusStratumResponse(boost::json::object packet, bool isDev)
// {
//   // if (!isDev) {
//   // if (!packet.contains("id")) return 0;
//   int64_t id = packet["id"].to_number<int64_t>();
//   // std::cout << "Stratum packet: " << boost::json::serialize(packet).c_str() << std::endl;

//   switch (id)
//   {
//     case SpectreStratum::subscribeID:
//     {
//       std::cout << boost::json::serialize(packet).c_str() << std::endl;
//       if (packet["error"].is_null()) return 0;
//       else {
//         const char *errorMsg = packet["error"].get_string().c_str();
//         setcolor(RED);
//         printf("\n");
//         if (isDev) {
//           setcolor(CYAN);
//           printf("DEV | ");
//         }
//         printf("Stratum ERROR: %s\n", errorMsg);
//         fflush(stdout);
//         return -1;
//       }
//     }
//     break;
//     case SpectreStratum::submitID:
//     {
//       printf("\n");
//       if (isDev)
//       {
//         setcolor(CYAN);
//         printf("DEV | ");
//       }
//       if (!packet["result"].is_null() && packet.at("result").get_bool())
//       {
//         if (!isDev) accepted++;
//         std::cout << "Stratum: share accepted" << std::endl;
//         fflush(stdout);
//         setcolor(BRIGHT_WHITE);
//       }
//       else
//       {
//         if (!isDev) rejected++;
//         if (!isDev)
//           setcolor(RED);

//         boost::json::string ERR;
//         if (packet["error"].is_array()) {
//           ERR = packet.at("error").as_array()[1].as_string();
//         } else {
//           ERR = packet.at("error").at("message").get_string();
//         }
//         std::cout << "Stratum: share rejected: " << ERR.c_str() << std::endl;
        
//         fflush(stdout);
//         setcolor(BRIGHT_WHITE);
//       }
//       break;
//     }
//   }
//   return 0;
// }

void verus_stratum_session(
    std::string host,
    std::string const &port,
    std::string const &wallet,
    std::string const &worker,
    net::io_context &ioc,
    ssl::context &ctx,
    net::yield_context yield,
    bool isDev)
{
  ctx.set_options(boost::asio::ssl::context::default_workarounds |
                  boost::asio::ssl::context::no_sslv2 |
                  boost::asio::ssl::context::no_sslv3 |
                  boost::asio::ssl::context::no_tlsv1 |
                  boost::asio::ssl::context::no_tlsv1_1);

  beast::error_code ec;
  boost::system::error_code jsonEc;

  std::cerr << "[wave39] verus_stratum_session start isDev=" << (isDev ? 1 : 0)
            << " host=" << host << " port=" << port << std::endl;

  auto endpoint = resolve_host(wsMutex, ioc, yield, host, port);
  std::cerr << "[wave39] WAVE39_VERUS_CONNECT_LOG endpoint="
            << endpoint.address().to_string() << ":" << endpoint.port()
            << " isDev=" << (isDev ? 1 : 0) << std::endl;
  boost::beast::tcp_stream stream(ioc);

  // Set a timeout on the operation
  beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));

  // Make the connection on the IP address we get from a lookup
  beast::get_lowest_layer(stream).async_connect(endpoint, yield[ec]);
  if (ec)
    return fail(ec, "connect");
  std::cerr << "[wave39] verus connect ok isDev=" << (isDev ? 1 : 0) << std::endl;

  std::string minerName = "tnn-miner/" + std::string(versionString);
  boost::json::object packet;

  SpectreStratum::jobCache jobCache;
  std::string wave37CurrentTarget;
  std::string wave37PoolNonce;
  std::string wave37WorkerName = wallet + "." + worker;

  // Subscribe to Stratum
  packet = SpectreStratum::stratumCall;
  packet["id"] = SpectreStratum::subscribe.id;
  packet["method"] = SpectreStratum::subscribe.method;
  packet["params"] = boost::json::array({
    minerName
  });
  std::string subscription = boost::json::serialize(packet) + "\n";

  // std::cout << authResString << std::endl;
  size_t trans;

  try {
    beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));
    std::cerr << "[wave39] verus send subscribe isDev=" << (isDev ? 1 : 0) << " payload=" << subscription;
    trans = boost::asio::async_write(stream, boost::asio::buffer(subscription), yield[ec]);
    if (ec)
      return fail(ec, "Stratum subscribe");

    boost::asio::streambuf subRes;
    beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));
    trans = boost::asio::read_until(stream, subRes, "\n");

    std::string subResString = beast::buffers_to_string(subRes.data());
    subRes.consume(trans);
    if (jsonEc)
    {
      std::cerr << jsonEc.message() << std::endl;
    }

    std::cout << "sub result: " << subResString << std::endl << std::flush;

    std::stringstream  jsonStream(subResString);
    std::vector<std::string> packets;

    std::string line;
    while(std::getline(jsonStream,line,'\n'))
    {
      packets.push_back(line);
    }

    for (std::string packet : packets) {
      boost::json::object subRPC = boost::json::parse(packet.c_str()).as_object();
      if (!subRPC.contains("method") && subRPC.if_contains("result") && subRPC.at("result").is_array()) {
        auto result = subRPC.at("result").as_array();
        if (result.size() > 1 && result[1].is_string()) {
          wave37PoolNonce = result[1].as_string().c_str();
        }
      }
      if (subRPC.contains("method"))
      {
        // handleSpectreStratumPacket(subRPC, &jobCache, isDev);
      } 
    }
  } catch (const std::exception &e) {
    setcolor(RED);
    printf("\nStratum Subscribe error: %s\n", e.what());
    fflush(stdout);
    setcolor(BRIGHT_WHITE);
  }
  // Authorize Stratum Worker
  packet = SpectreStratum::stratumCall;
  packet.at("id") = SpectreStratum::authorize.id;
  packet.at("method") = SpectreStratum::authorize.method;
  packet.at("params") = boost::json::array({wallet + "." + worker, stratumPassword});

  std::string authorization = boost::json::serialize(packet) + "\n";

  // std::cout << authorization << std::endl;
  try {
    beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));
    std::cerr << "[wave39] verus send authorize isDev=" << (isDev ? 1 : 0) << std::endl;
    boost::asio::async_write(stream, boost::asio::buffer(authorization), yield[ec]);
    if (ec)
      return fail(ec, "Stratum authorize");

    boost::asio::streambuf authRes;
    beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));
    trans = boost::asio::read_until(stream, authRes, "\n");

    std::string authResString = beast::buffers_to_string(authRes.data());
    authRes.consume(trans);
    if (jsonEc)
    {
      std::cerr << jsonEc.message() << std::endl;
    }

    std::cout << "auth result: " << authResString << std::endl << std::flush;

    std::stringstream  jsonStream(authResString);
    std::vector<std::string> packets;

    std::string line;
    while(std::getline(jsonStream,line,'\n'))
    {
      packets.push_back(line);
    }

    for (std::string packet : packets) {
      boost::json::object authRPC = boost::json::parse(packet.c_str()).as_object();
      if (authRPC.contains("method"))
      {
        // handleSpectreStratumPacket(authRPC, &jobCache, isDev);
      }
    }
  } catch (const std::exception &e) {
    setcolor(RED);
    printf("\nStratum Authorize error: %s\n", e.what());
    fflush(stdout);
    setcolor(BRIGHT_WHITE);
  }
  // SpectreStratum::stratumCall;
  // packet.at("id") = SpectreStratum::subscribe.id;
  // packet.at("method") = SpectreStratum::subscribe.method;
  // packet.at("params") = {minerName};

  // beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));
  // trans = boost::asio::read_until(stream, subRes, "\n");

  // std::string subResString = beast::buffers_to_string(subRes.data());
  // subRes.consume(trans);

  // mutex.lock();
  // printf("before packet\n");
  // std::cout << subResString << std::endl;

  // printf("before parse\n");
  // mutex.unlock();
  // boost::json::object subResJson = boost::json::parse(subResString.c_str(), jsonEc).as_object();
  // if (jsonEc)
  // {
  //   std::cerr << jsonEc.message() << std::endl;
  // }

  // printf("after parse\n");

  // handleXStratumPacket(subResJson, isDev);

  // // This buffer will hold the incoming message
  // beast::flat_buffer buffer;
  // std::stringstream workInfo;

  SpectreStratum::jobTimeout = wave41VerusJobTimeoutSeconds();
  wave41TouchVerusJobClock();

  std::string chopQueue = "NULL";

  bool submitThread = false;
  bool abort = false;

  std::thread subThread([&](){
    submitThread = true;
    while(!abort) {
      std::unique_lock<std::mutex> lock(mutex);
      bool *B = isDev ? &submittingDev : &submitting;
      cv.wait(lock, [&]{ return (data_ready && (*B)) || abort; });
      if (abort) break;
      try {
        boost::json::object *S = &share;
        if (isDev)
          S = &devShare;
        hoist_rpc_id(*S);

        boost::system::error_code ec;
        std::string msg = boost::json::serialize((*S)) + "\n";
        if (!isDev) {
          int limit = wave39UserSubmitLimit();
          if (limit >= 0) {
            int current = wave39UserSubmitCount.load();
            if (current >= limit) {
              std::cerr << "[wave39] WAVE39_SUBMIT_LIMIT_BLOCK limit=" << limit
                        << " current=" << current << std::endl;
              abort = true;
              break;
            }
            int allowed = wave39UserSubmitCount.fetch_add(1) + 1;
            std::cerr << "[wave39] WAVE39_SUBMIT_LIMIT_ALLOW count=" << allowed
                      << " limit=" << limit << std::endl;
          }
        }
        // std::cout << "sending in: " << msg << std::endl;
        beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(1));
        boost::asio::async_write(stream, boost::asio::buffer(msg), [&](const boost::system::error_code& error, std::size_t bytes_transferred) {
          if (error) {
            printf("error on write: %s\n", error.message().c_str());
            fflush(stdout);
            abort = true;
          }
          if (!isDev) SpectreStratum::lastShareSubmissionTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
          // (*B) = false;
          // data_ready = false;
        });
        (*B) = false;
        data_ready = false;
      } catch (const std::exception &e) {
        setcolor(RED);
        printf("\nSubmit thread error: %s\n", e.what());
        fflush(stdout);
        setcolor(BRIGHT_WHITE);
        break;
      }
      std::this_thread::yield();
    }
    submitThread = false;
  });

  boost::asio::streambuf response;

  while (!ABORT_MINER)
  {
    bool *C = isDev ? &devConnected : &isConnected;
    bool *B = isDev ? &submittingDev : &submitting;
    try
    {
      if (
          SpectreStratum::lastReceivedJobTime > 0 &&
          wave41NowSeconds() - SpectreStratum::lastReceivedJobTime > SpectreStratum::jobTimeout)
      {
        setcolor(RED);
        printf("timeout\n");
        fflush(stdout);
        setcolor(BRIGHT_WHITE);
        setForDisconnected(C, B, &abort, &data_ready, &cv);

        for (;;) {
          if (!submitThread) break;
          std::this_thread::yield();
        }
        if (subThread.joinable()) subThread.join();
        stream.close();
        return fail(ec, "Stratum session timed out");
      }

      std::stringstream workInfo;
      beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(wave41VerusReadTimeoutSeconds()));

      trans = boost::asio::async_read_until(stream, response, "\n", yield[ec]);
      if (ec) {
        setcolor(RED);
        printf("failed to read: %s\n", isDev ? "dev" : "user");
        fflush(stdout);
        setcolor(BRIGHT_WHITE);
        setForDisconnected(C, B, &abort, &data_ready, &cv);
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        cv.notify_all();

        for (;;) {
          if (!submitThread) {
            break;
          }
          std::this_thread::yield();
        }
        if (subThread.joinable()) subThread.join();
        stream.close();
        return fail(ec, "async_read");
      }

      if (trans > 0)
      {
        wave41TouchVerusJobClock();
        // std::scoped_lock<std::mutex> lockGuard(wsMutex);
        std::vector<std::string> packets;
        std::istream responseStream(&response);
        std::string data;
        std::getline(responseStream, data);
        data += "\n";

        std::cout << "received: " << data << std::endl << std::flush;
        // printf("received data\n");
        fflush(stdout);

        std::stringstream  jsonStream(data);

        std::string line;
        while(std::getline(jsonStream,line,'\n'))
        {
          packets.push_back(line);
        }

        for (std::string packet : packets) {
          try {
            boost::json::object sRPC = boost::json::parse(packet.c_str()).as_object();
            wave37HandleVerusPacketForSnapshot(sRPC, wave37WorkerName, wave37CurrentTarget, wave37PoolNonce);
          } catch (const std::exception &) {
          }
        }

        /*
        for (std::string packet : packets) {
          try {
            boost::json::object sRPC = boost::json::parse(packet.c_str()).as_object();
            if (sRPC.contains("method"))
            {
              if (std::string(sRPC.at("method").as_string().c_str()).compare(SpectreStratum::s_ping) == 0)
              {
                boost::json::object pong({{"id", sRPC.at("id").get_uint64()},
                                          {"method", SpectreStratum::pong.method}});
                std::string pongPacket = std::string(boost::json::serialize(pong).c_str()) + "\n";
                trans = boost::asio::async_write(
                    stream,
                    boost::asio::buffer(pongPacket),
                    yield[ec]);
                if(ec) {
                  printf("error on write(%zu): %s\n", trans, ec.message().c_str());
                  fflush(stdout);
                }
                if (ec && trans > 0) {
                  setcolor(RED);
                  printf("ec && trans > 0\n");
                  fflush(stdout);
                  setcolor(BRIGHT_WHITE);
                  setForDisconnected(C, B, &abort, &data_ready, &cv);

                  for (;;)
                  {
                    if (!submitThread)
                      break;
                    std::this_thread::yield();
                  }
                  stream.close();
                  return fail(ec, "Stratum pong");
                }
              }
              else
                handleSpectreStratumPacket(sRPC, &jobCache, isDev);
            }
            else
            {
              handleSpectreStratumResponse(sRPC, isDev);
            } 
          } catch(const std::exception &e){
            // printf("\n\n packet count: %d, msg size: %llu\n\n", packets.size(), trans);
            setcolor(RED);
            // printf("BEFORE PACKET\n");
            // std::cout << "BAD PACKET: " << packet << std::endl;
            // printf("AFTER PACKET\n");
            // std::cerr << e.what() << std::endl;
            setcolor(BRIGHT_WHITE);
            bool tryParse = (chopQueue.compare("NULL") != 0);

            if (tryParse) {
              chopQueue += packet;
              // printf("resulting json string: %s\n\n", chopQueue.c_str());
              try
              {
                packets.clear();
                boost::json::object sRPC = boost::json::parse(chopQueue.c_str()).as_object();
                if (sRPC.contains("method"))
                {
                  if (std::string(sRPC.at("method").as_string().c_str()).compare(SpectreStratum::s_ping) == 0)
                  {
                    boost::json::object pong({{"id", sRPC.at("id").get_uint64()},
                                              {"method", SpectreStratum::pong.method}});
                    std::string pongPacket = std::string(boost::json::serialize(pong).c_str()) + "\n";
                    trans = boost::asio::async_write(
                        stream,
                        boost::asio::buffer(pongPacket),
                        yield[ec]);
                    if(ec) {
                      printf("error on write(%zu): %s\n", trans, ec.message().c_str());
                      fflush(stdout);
                    }
                    if (ec && trans > 0) {
                      printf("ec && trans > 0\n");
                      fflush(stdout);
                      setForDisconnected(C, B, &abort, &data_ready, &cv);
  
                      for (;;)
                      {
                        if (!submitThread) {
                          break;
                        }
                        std::this_thread::yield();
                      }
                      stream.close();
                      return fail(ec, "Stratum pong");
                    }
                  }
                  else
                    handleSpectreStratumPacket(sRPC, &jobCache, isDev);
                }
                else
                {
                  handleSpectreStratumResponse(sRPC, isDev);
                }
                chopQueue = "NULL";
                // printf("COMBINE WORKED!\n\n");
              }
              catch (const std::exception &e)
              {
                setcolor(RED);
                printf("COMBINE FAILED\n\nBEFORE PACKET\n");
                std::cout << chopQueue << std::endl;
                printf("AFTER PACKET\n");
                std::cerr << e.what() << std::endl;
                fflush(stdout);
                setcolor(BRIGHT_WHITE);
              }
            } else {
              chopQueue = packet;
              // printf("partial json start = %s\n", chopQueue.c_str());
            } 
          }
        }*/
      }
    }
    catch (const std::exception &e)
    {
      bool *C = isDev ? &devConnected : &isConnected;
      printf("exception\n");
      fflush(stdout);
      setForDisconnected(C, B, &abort, &data_ready, &cv);

        for (;;) {
          if (!submitThread) break;
          std::this_thread::yield();
        }
      if (subThread.joinable()) subThread.join();
      stream.close();
      setcolor(RED);
      std::cerr << e.what() << std::endl;
      fflush(stdout);
      setcolor(BRIGHT_WHITE);
      return fail(ec, "Stratum session error");
    }
    std::this_thread::yield();
    if(ABORT_MINER) {
      bool *connPtr = isDev ? &devConnected : &isConnected;
      bool *submitPtr = isDev ? &submittingDev : &submitting;
      setForDisconnected(connPtr, submitPtr, &abort, &data_ready, &cv);
      ioc.stop();
    }
  }
  cv.notify_all();

  if (subThread.joinable()) subThread.join();

  // printf("\n\n\nflagged connection loss\n");
  // stream.close();
}

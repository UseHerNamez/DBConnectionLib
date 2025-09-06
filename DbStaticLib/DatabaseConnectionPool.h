#pragma once

#include <memory>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <string>
#include <atomic>
#include <chrono>
#include <thread>
#include "DatabaseConnector.h"
#include "EncryptionUtils.h"

class DatabaseConnectionPool {
public:

    DatabaseConnectionPool(const std::string& encryptedConfigPath,
        const std::string& key,
        uint32_t initialPoolSize = 10, // ctor which will accept desired poolsize
        uint32_t numReservedWriters = 0); 

    ~DatabaseConnectionPool();

    std::shared_ptr<DatabaseConnector> Acquire();
    std::shared_ptr<DatabaseConnector> Acquire(std::chrono::milliseconds timeout, bool bIsWriter);

private:
    void HealthCheckLoop();
    bool IsConnectionValid(const std::shared_ptr<DatabaseConnector>& conn);
    void RefillPoolIfNeeded();
    auto createNewConnection()->std::shared_ptr<DatabaseConnector>;
    static std::chrono::milliseconds NextBackoff(std::chrono::milliseconds current);

    uint32_t reservedWriterCount_ = 0;
    uint32_t poolSize = 10;
    const int timeToWaitForAFreeConn = 5000;
    std::string encryptedConfigPath_;
    std::string key_;
    std::string address;
    std::string username;
    std::string password;
    std::string sslCa;

    std::vector<std::shared_ptr<DatabaseConnector>> connections_;
    std::queue<std::shared_ptr<DatabaseConnector>> freeConnections_;

    std::mutex mutex_;
    std::condition_variable condition_;

    std::thread healthCheckThread_;
    std::atomic<bool> stopHealthCheck_;

    // Backoff state
    std::chrono::steady_clock::time_point nextRefillAttempt_{ std::chrono::steady_clock::now() };
    std::chrono::milliseconds refillBackoffMs_{ 0 };


};


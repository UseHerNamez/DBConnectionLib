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

class DatabaseConnectionPool {
public:

    DatabaseConnectionPool(const std::string& encryptedConfigPath,
        const std::string& key);

    ~DatabaseConnectionPool();

    std::shared_ptr<DatabaseConnector> Acquire();

private:
    void HealthCheckLoop();
    bool IsConnectionValid(std::shared_ptr<DatabaseConnector>& conn);
    void RefillPoolIfNeeded();

    const size_t poolSize = 10;
    std::string encryptedConfigPath_;
    std::string key_;

    std::vector<std::shared_ptr<DatabaseConnector>> connections_;
    std::queue<std::shared_ptr<DatabaseConnector>> freeConnections_;

    std::mutex mutex_;
    std::condition_variable condition_;

    std::thread healthCheckThread_;
    std::atomic<bool> stopHealthCheck_;
};


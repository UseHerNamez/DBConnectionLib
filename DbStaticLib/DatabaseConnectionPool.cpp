#include "pch.h"
#include "DatabaseConnectionPool.h"

DatabaseConnectionPool::DatabaseConnectionPool(
    const std::string& encryptedConfigPath,
    const std::string& key)
{
    for (size_t i = 0; i < poolSize; ++i) {
        auto conn = std::make_shared<DatabaseConnector>(encryptedConfigPath, key, IV); //IV from EncryptionUtils.h
        conn->ConnectToDatabase();
        connections_.push_back(conn);
        freeConnections_.push(conn);
    }
    stopHealthCheck_ = false;
    healthCheckThread_ = std::thread(&DatabaseConnectionPool::HealthCheckLoop, this);
}

DatabaseConnectionPool::~DatabaseConnectionPool() {
    stopHealthCheck_ = true;
    condition_.notify_all();  // Just in case it’s sleeping or waiting
    if (healthCheckThread_.joinable()) {
        healthCheckThread_.join();  // Clean shutdown
    }
}

std::shared_ptr<DatabaseConnector> DatabaseConnectionPool::Acquire()
{
    std::unique_lock<std::mutex> lock(mutex_);

    // Wait until a connection is available
    condition_.wait(lock, [this]() { return !freeConnections_.empty(); });

    // Get a connection from the queue
    auto conn = freeConnections_.front();
    freeConnections_.pop();

    // Wrap connection in a shared_ptr with a custom deleter that returns it to the pool
    return std::shared_ptr<DatabaseConnector>(
        conn.get(), //shared_ptr has a constructor which takes: 1. the pointer (conn.get) and 2. a custom delete function... lambda is the deleter.
        [this](DatabaseConnector* ptr) {
            std::unique_lock<std::mutex> lock(mutex_);
            freeConnections_.push(std::shared_ptr<DatabaseConnector>(ptr, [](DatabaseConnector*) {}));
            // The inner shared_ptr with empty deleter prevents double deletion
            condition_.notify_one();
        });
}

void DatabaseConnectionPool::HealthCheckLoop()
{
    while (!stopHealthCheck_)
    {
        std::this_thread::sleep_for(std::chrono::minutes(15));

        std::lock_guard<std::mutex> lock(mutex_);

        size_t size = freeConnections_.size();
        std::queue<std::shared_ptr<DatabaseConnector>> updatedQueue;

        for (size_t i = 0; i < size; ++i)
        {
            auto conn = freeConnections_.front();
            freeConnections_.pop();

            if (!conn || !conn->IsHealthy())
            {
                // Recreate the connection
                auto newConn = std::make_shared<DatabaseConnector>(encryptedConfigPath_, key_, IV);
                if (newConn->GetConnectedFlag())
                    newConn->ConnectToDatabase();

                updatedQueue.push(newConn);
            }
            else
            {
                updatedQueue.push(conn);
            }
        }

        // Replace the old queue with the updated one
        std::swap(freeConnections_, updatedQueue);
    }
}

bool DatabaseConnectionPool::IsConnectionValid(const std::shared_ptr<DatabaseConnector>& conn)
{
    if (!conn) return false;

    return conn->IsHealthy();
}

void DatabaseConnectionPool::RefillPoolIfNeeded()
{
    std::lock_guard<std::mutex> lock(mutex_);

    // Remove invalid connections from both queues and vector
    connections_.erase(
        std::remove_if(connections_.begin(), connections_.end(),
            [this](const std::shared_ptr<DatabaseConnector>& conn) {
                return !IsConnectionValid(conn);
            }),
        connections_.end()
                );

    std::queue<std::shared_ptr<DatabaseConnector>> newQueue;
    while (!freeConnections_.empty()) {
        auto conn = freeConnections_.front();
        freeConnections_.pop();

        if (IsConnectionValid(conn)) {
            newQueue.push(conn);
        }
    }
    std::swap(freeConnections_, newQueue);

    // Refill to maintain poolSize
    while (connections_.size() < poolSize) {
        auto newConn = std::make_shared<DatabaseConnector>(encryptedConfigPath_, key_, IV);
        newConn->ConnectToDatabase();

        if (newConn->GetConnectedFlag()) {
            connections_.push_back(newConn);
            freeConnections_.push(newConn);
        }
        else {
            // Optional: log the failed connection attempt
            break; // prevent infinite loop if DB is down
        }
    }

    // Notify waiting threads that a connection might now be available
    condition_.notify_all();
}



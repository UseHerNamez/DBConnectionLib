#include "pch.h"
#include "DatabaseConnectionPool.h"
#include <mysqlx/xdevapi.h>

DatabaseConnectionPool::DatabaseConnectionPool(
    const std::string& encryptedConfigPath,
    const std::string& key)
    : encryptedConfigPath_(encryptedConfigPath), key_(key), stopHealthCheck_(false)
{
    // 1. Read and decrypt config
    std::ifstream encryptedConfigFile(encryptedConfigPath_, std::ios::binary);
    if (!encryptedConfigFile.is_open()) {
        throw std::runtime_error("Failed to open encrypted configuration file.");
    }

    std::string encryptedCredentials((std::istreambuf_iterator<char>(encryptedConfigFile)),
        std::istreambuf_iterator<char>());
    encryptedConfigFile.close();

    std::string decryptedCredentials = decrypt(encryptedCredentials, key_);
    if (decryptedCredentials.empty()) {
        throw std::runtime_error("Failed to decrypt credentials.");
    }

    // 2. Parse config values
    std::istringstream decryptedStream(decryptedCredentials);
    std::string line;

    while (std::getline(decryptedStream, line)) {
        size_t separatorPos = line.find('=');
        if (separatorPos == std::string::npos) continue;

        std::string key = line.substr(0, separatorPos);
        std::string value = line.substr(separatorPos + 1);

        key.erase(std::remove_if(key.begin(), key.end(), ::isspace), key.end());
        value.erase(std::remove_if(value.begin(), value.end(), ::isspace), value.end());
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);

        if (key == "address") address = value;
        else if (key == "username") username = value;
        else if (key == "password") password = value;
        else if (key == "sslca") sslCa = value;
    }

    // 3. Create connections individually, each with its own Session
    try {
        for (size_t i = 0; i < poolSize; ++i) {
            mysqlx::SessionSettings settings(
                address, 33060,
                username,
                password,
                sslCa.empty() ? nullptr : sslCa.c_str()
            );

            auto session = std::make_shared<mysqlx::Session>(settings);
            auto conn = std::make_shared<DatabaseConnector>(session);
            connections_.push_back(conn);
            freeConnections_.push(conn);
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "Failed to create MySQL session: " << err.what() << std::endl;
        throw;
    }

    // Start health check thread
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
    condition_.wait(lock, [this]() { return !freeConnections_.empty(); });

    auto conn = freeConnections_.front();
    freeConnections_.pop();

    return std::shared_ptr<DatabaseConnector>(
        conn.get(),
        [this](DatabaseConnector* ptr) {
            std::unique_lock<std::mutex> lock(mutex_);
            freeConnections_.push(std::shared_ptr<DatabaseConnector>(ptr, [](DatabaseConnector*) {}));
            condition_.notify_one();
        }
    );
}

void DatabaseConnectionPool::HealthCheckLoop()
{
    while (!stopHealthCheck_) {
        std::this_thread::sleep_for(std::chrono::minutes(15));
        std::lock_guard<std::mutex> lock(mutex_);

        std::queue<std::shared_ptr<DatabaseConnector>> updatedQueue;

        while (!freeConnections_.empty()) {
            auto conn = freeConnections_.front();
            freeConnections_.pop();

            if (!conn || !conn->IsHealthy()) {
                std::cerr << "Unhealthy connection detected. Replacing it..." << std::endl;

                auto newConn = createNewConnection();
                if (newConn && newConn->GetConnectedFlag()) {
                    updatedQueue.push(newConn);

                    // Also update the main connection vector
                    auto it = std::find(connections_.begin(), connections_.end(), conn);
                    if (it != connections_.end()) {
                        *it = newConn;
                    }
                }
                else {
                    std::cerr << "Failed to create replacement connection during health check." << std::endl;
                    // Don't push the bad one back in — let RefillPoolIfNeeded handle adding a new one later
                }
            }
            else {
                updatedQueue.push(conn);
            }
        }

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

    // Remove invalid connections from vector and free queue
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

    // Refill pool to maintain poolSize
    while (connections_.size() < poolSize) {
        auto newConn = createNewConnection();
        if (newConn && newConn->GetConnectedFlag()) {
            connections_.push_back(newConn);
            freeConnections_.push(newConn);
        }
        else {
            break; // what if db is down?
        }
    }
    condition_.notify_all();
}

auto DatabaseConnectionPool::createNewConnection() -> std::shared_ptr<DatabaseConnector> {
    try {
        mysqlx::SessionSettings settings(
            address, 33060,
            username,
            password,
            sslCa.empty() ? nullptr : sslCa.c_str()
        );
        auto session = std::make_shared<mysqlx::Session>(settings);
        return std::make_shared<DatabaseConnector>(session);
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "Failed to create MySQL session: " << err.what() << std::endl;
        return nullptr;
    }
}

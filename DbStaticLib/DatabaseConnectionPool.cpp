#include "pch.h"
#include "DatabaseConnectionPool.h"
#include <mysqlx/xdevapi.h>

DatabaseConnectionPool::DatabaseConnectionPool(
    const std::string& encryptedConfigPath,
    const std::string& key, uint32_t initialPoolSize, uint32_t numReservedWriters)
    : encryptedConfigPath_(encryptedConfigPath), key_(key), poolSize(initialPoolSize), stopHealthCheck_(false), reservedWriterCount_(numReservedWriters)
{
    // 1. Read and decrypt config
    std::ifstream encryptedConfigFile(encryptedConfigPath_, std::ios::binary);
    if (!encryptedConfigFile.is_open()) {
        throw std::runtime_error("Failed to open encrypted configuration file.");
    }

    std::string encryptedCredentials((std::istreambuf_iterator<char>(encryptedConfigFile)), std::istreambuf_iterator<char>());
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

std::shared_ptr<DatabaseConnector> DatabaseConnectionPool::Acquire(std::chrono::milliseconds timeout, bool bIsWriter)
{
    using clock = std::chrono::steady_clock;

    std::unique_lock<std::mutex> lock(mutex_);
    const auto deadline = clock::now() + timeout;

    // Lambda to check if we can take a connection
    auto canAcquire = [this, bIsWriter]() -> bool {
        if (freeConnections_.empty()) return false;

        if (!bIsWriter)
        {
            // For non-writers, ensure at least 'reservedWriterCount_' connections remain free
            return freeConnections_.size() > reservedWriterCount_;
        }
        // Writers can take any free connection
        return true;
    };

    while (!canAcquire() && !stopHealthCheck_)
    {
        if (condition_.wait_until(lock, deadline) == std::cv_status::timeout)
        {
            return nullptr; // caller can respond with temporary DB unavailable
        }
    }

    if (stopHealthCheck_) return nullptr;

    // Take ownership of one connection
    auto conn = std::move(freeConnections_.front());
    freeConnections_.pop();

    // Return a shared_ptr that will push it back on release
    return std::shared_ptr<DatabaseConnector>(
        conn.get(),
        [this, conn = std::move(conn)](DatabaseConnector* /*ptr*/) mutable {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!stopHealthCheck_) {
            freeConnections_.push(std::move(const_cast<std::shared_ptr<DatabaseConnector>&>(conn)));
        }
        condition_.notify_one();
    }
    );
}

// Simple default Acquire (non-writer by default)
std::shared_ptr<DatabaseConnector> DatabaseConnectionPool::Acquire()
{
    return Acquire(std::chrono::milliseconds{ timeToWaitForAFreeConn }, false);
}


void DatabaseConnectionPool::HealthCheckLoop()
{
    using namespace std::chrono;

    while (!stopHealthCheck_) {
        // Sleep in small chunks so stopHealthCheck_ can end promptly
        for (int i = 0; i < 15 * 60 && !stopHealthCheck_; ++i) { // 15 minutes
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (stopHealthCheck_) break;

        // 1) Take a snapshot of free connections
        std::vector<std::shared_ptr<DatabaseConnector>> batch;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            while (!freeConnections_.empty()) {
                batch.push_back(std::move(freeConnections_.front()));
                freeConnections_.pop();
            }
        }

        // 2) Check and replace outside the lock
        std::vector<std::shared_ptr<DatabaseConnector>> back;
        back.reserve(batch.size());
        const bool canCreateNow = std::chrono::steady_clock::now() >= nextRefillAttempt_;

        for (auto& con : batch) {
            if (con && con->IsHealthy()) {
                back.push_back(std::move(con));
                continue;
            }

            std::shared_ptr<DatabaseConnector> replacement;
            if (canCreateNow) {
                replacement = createNewConnection();
            }

            if (replacement && replacement->GetConnectedFlag()) {
                back.push_back(std::move(replacement));
                // success clears backoff
                std::lock_guard<std::mutex> lock(mutex_);
                refillBackoffMs_ = std::chrono::milliseconds{ 0 };
                nextRefillAttempt_ = std::chrono::steady_clock::now();
            }
            else {
                // do not put the unhealthy connection back into freeConnections_ - RefillPoolIfNeeded will top us up with backoff
                if (canCreateNow) {
                    std::lock_guard<std::mutex> lock(mutex_);
                    refillBackoffMs_ = NextBackoff(refillBackoffMs_);
                    nextRefillAttempt_ = std::chrono::steady_clock::now() + refillBackoffMs_;
                }
            }
        }

        // 3) Return the checked connections and try to refill
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto& c : back) {
                freeConnections_.push(std::move(c));
            }
            condition_.notify_all();
        }

        RefillPoolIfNeeded(); // uses the same backoff state
    }
}

bool DatabaseConnectionPool::IsConnectionValid(const std::shared_ptr<DatabaseConnector>& conn)
{
    if (!conn) return false;

    return conn->IsHealthy();
}

void DatabaseConnectionPool::RefillPoolIfNeeded()
{
    using namespace std::chrono;

    // Step 1 - prune invalid, but do it quickly under the lock
    {
        std::lock_guard<std::mutex> lock(mutex_);

        // Remove invalid entries from connections_
        connections_.erase(
            std::remove_if(connections_.begin(), connections_.end(),
                [this](const std::shared_ptr<DatabaseConnector>& c) {
                    return !IsConnectionValid(c);
                }),
            connections_.end()
                    );

        // Filter freeConnections_ to valid only
        std::queue<std::shared_ptr<DatabaseConnector>> filtered;
        while (!freeConnections_.empty()) {
            auto c = freeConnections_.front();
            freeConnections_.pop();
            if (IsConnectionValid(c)) {
                filtered.push(std::move(c));
            }
        }
        std::swap(freeConnections_, filtered);

        // If we are still within a backoff window, do nothing now
        if (steady_clock::now() < nextRefillAttempt_) {
            return;
        }
    }

    // Step 2 - figure how many we need, and try to create them outside the lock
    size_t need = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (connections_.size() >= poolSize) return;
        need = poolSize - connections_.size();
    }

    std::vector<std::shared_ptr<DatabaseConnector>> made;
    made.reserve(need);

    for (size_t i = 0; i < need; ++i) {
        auto conn = createNewConnection();
        if (!conn || !conn->GetConnectedFlag()) {
            // failed - backoff and stop trying more right now
            break;
        }
        made.push_back(std::move(conn));
    }

    // Step 3 - commit results under the lock and adjust backoff
    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (!made.empty()) {
            for (auto& c : made) {
                connections_.push_back(c);
                freeConnections_.push(std::move(c));
            }
            // success - clear backoff
            refillBackoffMs_ = std::chrono::milliseconds{ 0 };
            nextRefillAttempt_ = std::chrono::steady_clock::now(); // ready immediately
            condition_.notify_all();
        }
        else {
            // all attempts failed - schedule next try with backoff
            refillBackoffMs_ = NextBackoff(refillBackoffMs_);
            nextRefillAttempt_ = std::chrono::steady_clock::now() + refillBackoffMs_;
        }
    }
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

std::chrono::milliseconds DatabaseConnectionPool::NextBackoff(std::chrono::milliseconds current) {
    using namespace std::chrono;
    constexpr milliseconds kStart{ 500 };   // first wait 0.5s
    constexpr milliseconds kMax{ 30000 };   // cap at 30s
    if (current.count() == 0) current = kStart; else current = current * 2;
    if (current > kMax) current = kMax;

    // tiny jitter 0-250ms to avoid sync storms across instances
    unsigned seed = static_cast<unsigned>(std::chrono::steady_clock::now().time_since_epoch().count());
    seed ^= static_cast<unsigned>(reinterpret_cast<uintptr_t>(&current));
    std::minstd_rand rng(seed);
    std::uniform_int_distribution<int> d(0, 250);
    current += milliseconds{ d(rng) };
    return current;
}
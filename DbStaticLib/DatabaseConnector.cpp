// DatabaseConnector.cpp
#include "pch.h"

// kill problematic macros coming from whatever pch.h pulled in
#include "MysqlxSanitize.h"

#include <mysqlx/xdevapi.h> // include MySQL AFTER cleaning macros. If not, it brought up some weird string and value errors from common.h file of vcpkg

#include "DatabaseConnector.h"
#include "EncryptionUtils.h"
#include <algorithm>

// aliases...
using MysqlxSession = mysqlx::abi2::r0::Session;
using MysqlxError = mysqlx::abi2::r0::Error;
using MysqlxSchema = mysqlx::abi2::r0::Schema;
using MysqlxTable = mysqlx::abi2::r0::Table;
using MysqlxRow = mysqlx::abi2::r0::Row;
using MysqlxRowResult = mysqlx::abi2::r0::RowResult;
namespace {
    constexpr const char* kSchema = "accounts_db";
    constexpr const char* kUsersTable = "user_table";
    constexpr const char* kCharactersTable = "characters_table";
    constexpr const char* kMapsTable = "maps";
}

DatabaseConnector::DatabaseConnector(std::shared_ptr<MysqlxSession> i_session)
    : session(std::move(i_session)), connectedFlag(true)
{
    if (!session) {
        std::cerr << "Warning: DatabaseConnector initialized with null session.\n";
        connectedFlag = false;
    }
}

DatabaseConnector::~DatabaseConnector()
{
    // shared_ptr will clean up - call close() explicitly just to be tidy
    if (session) {
        try {
            session->close();
        }
        catch (const MysqlxError& e) {
            std::cerr << "Error closing MySQL X session: " << e.what() << '\n';
        }
    }
}

bool DatabaseConnector::IsHealthy() const
{
    try {
        if (!session) return false;

        // Simple ping - will throw on failure
        session->sql("SELECT 1").execute();
        return true;
    }
    catch (const MysqlxError& e) {
        std::cerr << "IsHealthy failed: " << e.what() << '\n';
        return false;
    }
}

bool DatabaseConnector::DoesUsernameExist(const std::string& username)
{
    try {
        if (!session) {
            std::cerr << "Session is not initialized.\n";
            return false;
        }

        // TODO: consider making schema name configurable instead of hardcoded
        MysqlxSchema db = session->getSchema("accounts_db");
        MysqlxTable userTable = db.getTable("user_table");

        MysqlxRowResult result = userTable
            .select("COUNT(*) AS user_count")
            .where("username = :username")
            .bind("username", username)
            .execute();

        // Some drivers buffer rows lazily - fetchOne() is safest
        if (result.count() > 0) {
            if (auto row = result.fetchOne(); !row.isNull())
            {
                // prefer explicit get to avoid narrowing
                std::int64_t cnt = row[0].get<std::int64_t>();
                return cnt > 0;
            }
        }
    }
    catch (const MysqlxError& e) {
        std::cerr << "MySQL X Error: " << e.what() << '\n';
    }
    catch (const std::exception& ex) {
        std::cerr << "Standard Exception: " << ex.what() << '\n';
    }
    return false;
}

bool DatabaseConnector::DoPasswordsMatch(const std::string& username, const std::string& hashedPassword, std::string& token, int& userId)
{
    try {
        if (!session) {
            std::cerr << "Session is not initialized.\n";
            userId = -1;
            return false;
        }

        // TODO: replace with your actual schema name
        MysqlxSchema db = session->getSchema("accounts_db");
        MysqlxTable  user = db.getTable("user_table");

        MysqlxRowResult result = user
            .select("id", "password")
            .where("username = :username")
            .bind("username", username)
            .execute();

        if (result.count() == 0) {
            userId = -1;
            return false;
        }

        MysqlxRow row = result.fetchOne();
        // be explicit about types to avoid narrowing
        std::int64_t id64 = row[0].get<std::int64_t>();
        std::string  storedHashedPassword = row[1].get<std::string>();

        userId = static_cast<int>(id64);

        if (storedHashedPassword == hashedPassword) {
            std::unordered_map<std::string, std::string> claims = {
                {"username", username},
                {"userId", std::to_string(userId)}
            };
            token = GenerateToken(claims);
            return true;
        }
    }
    catch (const MysqlxError& e) {
        std::cerr << "MySQL X Error: " << e.what() << '\n';
    }
    catch (const std::exception& ex) {
        std::cerr << "Standard Exception: " << ex.what() << '\n';
    }

    userId = -1;
    return false;
}

bool DatabaseConnector::RegisterUser(const std::string& username,
    const std::string& hashedPassword,
    std::string& token)
{
    try {
        if (!session) {
            std::cerr << "Session is not initialized.\n";
            return false;
        }

        // TODO: replace with your actual schema name
        MysqlxSchema db = session->getSchema("accounts_db");
        MysqlxTable  user = db.getTable("user_table");

        user.insert("username", "password")
            .values(username, hashedPassword)
            .execute();

        // get last insert id
        MysqlxRowResult res = session->sql("SELECT LAST_INSERT_ID()").execute();
        if (res.count() == 0) {
            std::cerr << "Could not fetch LAST_INSERT_ID().\n";
            return false;
        }
        MysqlxRow row = res.fetchOne();
        std::int64_t id64 = row[0].get<std::int64_t>();
        int userId = static_cast<int>(id64);

        std::unordered_map<std::string, std::string> claims = {
            {"username", username},
            {"userId", std::to_string(userId)}
        };
        token = GenerateToken(claims);
        return true;
    }
    catch (const MysqlxError& err) {
        std::cerr << "MySQL X Error: " << err.what() << '\n';
    }
    catch (const std::exception& ex) {
        std::cerr << "Standard Exception: " << ex.what() << '\n';
    }
    return false;
}

bool DatabaseConnector::GetConnectedFlag() const
{
    return connectedFlag;
}

std::string DatabaseConnector::DeleteCharacter(int userId, const std::string& charName)
{
    try {
        if (!session) {
            std::cerr << "Session is not initialized.\n";
            return "DATABASE_ERROR NO_SESSION";
        }

        // TODO: replace with your actual schema and table names
        MysqlxSchema db = session->getSchema("accounts_db");
        MysqlxTable  characters = db.getTable("characters_table");

        auto cmd = characters.remove()
            .where("user_id = :user_id AND character_name = :char_name")
            .bind("user_id", userId)
            .bind("char_name", charName)
            .execute();

        std::uint64_t affected = cmd.getAffectedItemsCount();
        return affected > 0 ? "CHARACTER_DELETED" : "CHARACTER_NOT_FOUND";
    }
    catch (const MysqlxError& e) {
        std::cerr << "MySQL X Error while deleting character: " << e.what() << '\n';
        return "DATABASE_ERROR SQL_e";
    }
}

std::string DatabaseConnector::GetCharactersInfoByUserId(int userId) // only for login pages
{
    try {
        if (!session) {
            std::cerr << "Session is not initialized.\n";
            return "db_err";
        }

        MysqlxSchema db = session->getSchema(kSchema);
        MysqlxTable  characters = db.getTable(kCharactersTable);

        MysqlxRowResult result = characters
            .select("character_name", "level", "gender", "appearance")
            .where("user_id = :user_id")
            .bind("user_id", userId)
            .execute();

        std::string out;
        // optional micro-optimization
        if (auto n = result.count(); n > 0) out.reserve(static_cast<size_t>(n) * 32);

        for (auto row : result) {
            const std::string characterName = row[0].get<std::string>();
            const std::string level = row[1].get<std::string>();   // or to_string(row[1].get<int64_t>())
            const std::string gender = row[2].get<std::string>();
            const std::string appearance = row[3].get<std::string>();

            out += characterName; out += "|";
            out += level;         out += "|";
            out += gender;        out += "|";
            out += appearance;    out += "|";
        }

        if (out.empty()) return "EMPTY";
        return out;
    }
    catch (const MysqlxError& e) {
        std::cerr << "Database error: " << e.what() << '\n';
        return "db_err";
    }
    catch (const std::exception& ex) {
        std::cerr << "Standard exception: " << ex.what() << '\n';
        return "db_err";
    }
}

std::string DatabaseConnector::DoesCharacterNameExist(const std::string& charName)
{
    try {
        if (!session) {
            std::cerr << "Session is not initialized.\n";
            return "Database error: no session";
        }

        MysqlxSchema db = session->getSchema(kSchema);
        MysqlxTable  characters = db.getTable(kCharactersTable);

        MysqlxRowResult result = characters
            .select("COUNT(*)")
            .where("character_name = :charName")
            .bind("charName", charName)
            .execute();

        MysqlxRow row = result.fetchOne();
        if (row.isNull()) {
            return "available"; // no rows means no such character
        }

        const std::int64_t cnt = row[0].get<std::int64_t>();
        return cnt > 0 ? "exists" : "available";
    }
    catch (const MysqlxError& e) {
        std::cerr << "SQLException in DatabaseConnector::DoesCharacterNameExist: " << e.what() << '\n';
        return std::string("Database error: ") + e.what();
    }
    catch (const std::exception& ex) {
        std::cerr << "Standard exception: " << ex.what() << '\n';
        return std::string("Database error: ") + ex.what();
    }
}

std::string DatabaseConnector::AddCosmeticCharDataToDB(const int userId, const std::string& charData)
{
    std::string characterName, levelStr, genderStr, appearance;
    try {
        std::istringstream ss(charData);
        if (!std::getline(ss, characterName, '|') ||
            !std::getline(ss, levelStr, '|') ||
            !std::getline(ss, genderStr, '|') ||
            !std::getline(ss, appearance))
        {
            return "Error: Invalid input format.";
        }

        int gender = (genderStr == "true") ? 1 : (genderStr == "false" ? 0 : std::stoi(genderStr));
        int level = std::stoi(levelStr);

        if (!session) {
            std::cerr << "Session is not initialized.\n";
            return "Database error: no session";
        }

        MysqlxSchema db = session->getSchema(kSchema);
        MysqlxTable  characters = db.getTable(kCharactersTable);

        characters.insert("user_id", "character_name", "level", "gender", "appearance")
            .values(userId, characterName, level, gender, appearance)
            .execute();

        return "success";
    }
    catch (const std::invalid_argument& e) {
        return std::string("Error: Invalid level or gender value - ") + e.what();
    }
    catch (const MysqlxError& e) {
        return std::string("SQLException: ") + e.what();
    }
    catch (const std::exception& e) {
        return std::string("Exception: ") + e.what();
    }
}

std::optional<std::tuple<int, std::string, std::string>>
DatabaseConnector::getCharIdAndMap(int userId, const std::string& charName)
{
    try {
        if (!session) {
            std::cerr << "Session is not initialized.\n";
            return std::nullopt;
        }

        // Raw SQL is fine here since we JOIN across tables
        const std::string query =
            "SELECT c.id, c.current_map, m.gameplay_server_address "
            "FROM characters_table c "
            "LEFT JOIN maps m ON c.current_map = m.name "
            "WHERE c.user_id = ? AND c.character_name = ?";

        auto stmt = session->sql(query);
        stmt.bind(userId, charName);
        auto result = stmt.execute();
        MysqlxRow row = result.fetchOne();

        if (!row.isNull()) {
            int         charId = static_cast<int>(row[0].get<std::int64_t>());
            std::string mapName = row[1].isNull() ? std::string() : row[1].get<std::string>();
            std::string mapAddress = row[2].isNull() ? std::string() : row[2].get<std::string>();
            return std::make_tuple(charId, std::move(mapName), std::move(mapAddress));
        }
        return std::nullopt;
    }
    catch (const MysqlxError& e) {
        std::cerr << "MySQL X Error in getCharIdAndMap: " << e.what() << '\n';
        return std::nullopt;
    }
    catch (const std::exception& e) {
        std::cerr << "Standard Exception in getCharIdAndMap: " << e.what() << '\n';
        return std::nullopt;
    }
}

std::optional<std::tuple<std::string, std::string, int, std::string,  // name, level, gender, appearance
    int, int, int, int, int, int>>                       // str,dex,wis,luk,pur,vic
     DatabaseConnector::GetCharGameplayDataById(int charId)
{
    {
        lastError_.clear();
        try
        {
            std::string query =
                "SELECT c.character_name, c.level, c.gender, c.appearance, "
                "       s.str_stat, s.dex_stat, s.wis_stat, s.luk_stat, s.pur_stat, s.vic_stat "
                "FROM characters_table AS c "
                "LEFT JOIN character_base_stats AS s ON s.character_id = c.id "
                "WHERE c.id = :id";

            mysqlx::SqlResult res = session->sql(query)
                .bind("id", charId)
                .execute();

            if (auto row = res.fetchOne())
            {
                std::string name = row[0].get<std::string>();
                std::string level = row[1].get<std::string>();
                int         gender = row[2].isNull() ? -1 : row[2].get<int>();
                std::string appearance = row[3].get<std::string>();

                int str_stat = row[4].isNull() ? 0 : row[4].get<int>();
                int dex_stat = row[5].isNull() ? 0 : row[5].get<int>();
                int wis_stat = row[6].isNull() ? 0 : row[6].get<int>();
                int luk_stat = row[7].isNull() ? 0 : row[7].get<int>();
                int pur_stat = row[8].isNull() ? 0 : row[8].get<int>();
                int vic_stat = row[9].isNull() ? 0 : row[9].get<int>();

                return std::make_tuple(
                    name, level, gender, appearance,
                    str_stat, dex_stat, wis_stat, luk_stat, pur_stat, vic_stat
                );
            }

            // not found is not an error - just return nullopt
            return std::nullopt;
        }
        catch (const MysqlxError& err)
        {
            lastError_ = std::string("MySQL error: ") + err.what();
        }
        catch (const std::exception& ex)
        {
            lastError_ = std::string("STD exception: ") + ex.what();
        }
        catch (...)
        {
            lastError_ = "Unknown exception in GetCharGameplayDataById";
        }

        return std::nullopt;
    }
}

std::string DatabaseConnector::GetLastError() const
{
    return lastError_;
}


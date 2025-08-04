// DatabaseConnector.cpp
#include "pch.h"
#include "DatabaseConnector.h"
#include <algorithm>


DatabaseConnector::DatabaseConnector(std::shared_ptr<mysqlx::Session> i_session) : session(std::move(i_session)), connectedFlag(true)
{
    if (!this->session) {
        std::cerr << "Warning: DatabaseConnector initialized with null session." << std::endl;
        connectedFlag = false;
    }
}

/*void DatabaseConnector::ConnectToDatabase() {
    try {
        session = std::make_shared<mysqlx::Session>(
            mysqlx::SessionOption::HOST, address,
            mysqlx::SessionOption::PORT, 33060,
            mysqlx::SessionOption::USER, username,
            mysqlx::SessionOption::PWD, password,
            mysqlx::SessionOption::SSL_CA, sslCa
            );
        connectedFlag = true;
    }
    catch (const mysqlx::Error& e) {
        std::cerr << "MySQL X Error: " << e.what() << std::endl;
        connectedFlag = false;
    }
}*/

DatabaseConnector::~DatabaseConnector() {
    // shared_ptr session will automatically clean up
    // explicitly closes the session:
    if (session) {
        try {
            session->close();
        }
        catch (const mysqlx::Error& e) {
            std::cerr << "Error closing MySQL X session: " << e.what() << std::endl;
        }
    }
}

bool DatabaseConnector::IsHealthy() const {
    try {
        if (!session) {
            return false; // No session => not healthy
        }

        // Run a simple query to check connection health
        // In MySQL X DevAPI, use session->sql() to execute raw SQL
        session->sql("SELECT 1").execute();

        return true; // If no exception, connection is healthy
    }
    catch (const mysqlx::Error& e) {
        std::cerr << "IsHealthy failed: " << e.what() << std::endl;
        return false;
    }
}

bool DatabaseConnector::DoesUsernameExist(const std::string& username) {
    try {
        // Make sure session is valid
        if (!session) {
            std::cerr << "Session is not initialized." << std::endl;
            return false;
        }

        // Get schema, replace "your_database_name" with actual database name
        mysqlx::Schema db = session->getSchema("accounts_db");

        // Get the table
        mysqlx::Table userTable = db.getTable("user_table");

        // Run the query with a where clause
        mysqlx::RowResult result = userTable
            .select("COUNT(*) AS user_count")
            .where("username = :username")
            .bind("username", username)
            .execute();

        // Check the result
        if (result.count() > 0) {
            mysqlx::Row row = result.fetchOne();
            int userCount = row[0];  // or row["user_count"]
            return (userCount > 0);
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "MySQL X Error: " << err.what() << std::endl;
    }
    catch (const std::exception& ex) {
        std::cerr << "Standard Exception: " << ex.what() << std::endl;
    }
    return false;
}

bool DatabaseConnector::DoPasswordsMatch(const std::string& username, const std::string& hashedPassword,
    std::string& token, int& userId)
{
    try {
        if (!session) {
            std::cerr << "Session is not initialized." << std::endl;
            userId = -1;
            return false;
        }

        // Get the schema and table (replace "your_database_name" accordingly)
        mysqlx::Schema db = session->getSchema("your_database_name");
        mysqlx::Table userTable = db.getTable("user_table");

        // Select id and password where username = :username
        mysqlx::RowResult result = userTable
            .select("id", "password")
            .where("username = :username")
            .bind("username", username)
            .execute();

        mysqlx::Row row = result.fetchOne();
        if (!row) {
            // No such user
            userId = -1;
            return false;
        }

        userId = row[0];  // id
        std::string storedHashedPassword = row[1].get<std::string>();  // password

        // Compare passwords
        if (storedHashedPassword == hashedPassword) {
            std::unordered_map<std::string, std::string> claims = {
                {"username", username},
                {"userId", std::to_string(userId)}
            };
            token = GenerateToken(claims);
            return true;
        }
    }
    catch (const mysqlx::Error& e) {
        std::cerr << "MySQL X Error: " << e.what() << std::endl;
    }
    catch (const std::exception& ex) {
        std::cerr << "Standard Exception: " << ex.what() << std::endl;
    }

    userId = -1;
    return false;
}

bool DatabaseConnector::RegisterUser(const std::string& username, const std::string& hashedPassword, std::string& token) {
    try {
        // Get schema and table from session
        mysqlx::Schema db = session->getSchema("users"); // adjust your schema name accordingly
        mysqlx::Table userTable = db.getTable("user_table");

        // Insert the new user
        userTable.insert("username", "password")
            .values(username, hashedPassword)
            .execute();

        // Retrieve last insert ID (MySQL X API uses "LAST_INSERT_ID()" as an expression)
        mysqlx::RowResult res = session->sql("SELECT LAST_INSERT_ID()").execute();
        mysqlx::Row row = res.fetchOne();

        if (!row.isNull()) {
            int userId = row[0]; // last insert ID

            // Generate token as before
            std::unordered_map<std::string, std::string> claims = {
                {"username", username},
                {"userId", std::to_string(userId)}
            };
            token = GenerateToken(claims);
            return true;
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "MySQL X Error: " << err.what() << std::endl;
    }
    catch (const std::exception& ex) {
        std::cerr << "Standard Exception: " << ex.what() << std::endl;
    }
    return false;
}

bool DatabaseConnector::GetConnectedFlag()
{
    return connectedFlag;
}

std::string DatabaseConnector::DeleteCharacter(int userId, const std::string& charName)
{
    try {
        if (!session) {
            std::cerr << "Session is not initialized." << std::endl;
            return "DATABASE_ERROR NO_SESSION";
        }

        // Get schema and table (replace "your_database_name" with actual DB name)
        mysqlx::Schema db = session->getSchema("your_database_name");
        mysqlx::Table charactersTable = db.getTable("characters_table");

        // Perform the DELETE query with matching user_id and character_name
        uint64_t affectedRows = charactersTable
            .remove()
            .where("user_id = :user_id AND character_name = :char_name")
            .bind("user_id", userId)
            .bind("char_name", charName)
            .execute()
            .getAffectedItemsCount();

        if (affectedRows > 0) {
            return "CHARACTER_DELETED";
        }
        else {
            return "CHARACTER_NOT_FOUND";
        }
    }
    catch (const mysqlx::Error& e) {
        std::cerr << "MySQL X Error while deleting character: " << e.what() << std::endl;
        return "DATABASE_ERROR SQL_e";
    }
}

std::string DatabaseConnector::GetCharactersInfoByUserId(int userId) // only for login pages
{
    std::string charactersInfo;

    try {
        if (!session) {
            std::cerr << "Session is not initialized." << std::endl;
            return "db_err";
        }

        mysqlx::Schema db = session->getSchema("your_database_name");
        mysqlx::Table charactersTable = db.getTable("characters_table");

        mysqlx::RowResult result = charactersTable
            .select("character_name", "level", "gender", "appearance")
            .where("user_id = :user_id")
            .bind("user_id", userId)
            .execute();

        for (mysqlx::Row row : result) {
            std::string characterName = row[0].get<std::string>();
            std::string level = row[1].get<std::string>();
            std::string gender = row[2].get<std::string>();
            std::string appearance = row[3].get<std::string>();

            charactersInfo += characterName + "|" + level + "|" + gender + "|" + appearance + "|";
        }
    }
    catch (const mysqlx::Error& e) {
        std::cerr << "Database error: " << e.what() << std::endl;
        return "db_err";
    }
    catch (const std::exception& ex) {
        std::cerr << "Standard exception: " << ex.what() << std::endl;
        return "db_err";
    }

    if (charactersInfo.empty()) {
        charactersInfo = "EMPTY";
    }

    return charactersInfo;
}

std::string DatabaseConnector::DoesCharacterNameExist(const std::string& charName)
{
    std::string o_returnMsg;

    try {
        if (!session) {
            std::cerr << "Session is not initialized." << std::endl;
            return "Database error: no session";
        }

        mysqlx::Schema db = session->getSchema("your_database_name");
        mysqlx::Table charactersTable = db.getTable("characters_table");

        mysqlx::RowResult result = charactersTable
            .select("COUNT(*)")
            .where("character_name = :charName")
            .bind("charName", charName)
            .execute();

        mysqlx::Row row = result.fetchOne();
        if (!row) {
            return "available"; // no rows means no such character
        }

        bool exists = row[0].get<int>() > 0;
        o_returnMsg = exists ? "exists" : "available";
    }
    catch (const mysqlx::Error& e) {
        std::cerr << "SQLException in DatabaseConnector::DoesCharacterNameExist: " << e.what() << std::endl;
        return std::string("Database error: ") + e.what();
    }
    catch (const std::exception& ex) {
        std::cerr << "Standard exception: " << ex.what() << std::endl;
        return std::string("Database error: ") + ex.what();
    }

    return o_returnMsg;
}

std::string DatabaseConnector::AddCosmeticCharDataToDB(const int userId, const std::string& charData) {
    std::string characterName, levelStr, genderStr, appearance;
    int level, gender;

    try {
        // Parse the input string
        std::istringstream ss(charData);
        if (!std::getline(ss, characterName, '|') ||
            !std::getline(ss, levelStr, '|') ||
            !std::getline(ss, genderStr, '|') ||
            !std::getline(ss, appearance))
        {
            return "Error: Invalid input format.";
        }

        if (genderStr == "true") gender = 1;
        else if (genderStr == "false") gender = 0;
        else gender = std::stoi(genderStr);  // fallback if numeric string

        level = std::stoi(levelStr);

        if (!session) {
            std::cerr << "Session is not initialized." << std::endl;
            return "Database error: no session";
        }

        mysqlx::Schema db = session->getSchema("your_database_name");
        mysqlx::Table charactersTable = db.getTable("characters_table");

        // Insert the record
        charactersTable
            .insert("user_id", "character_name", "level", "gender", "appearance")
            .values(userId, characterName, level, gender, appearance)
            .execute();

        return "success";
    }
    catch (const std::invalid_argument& e) {
        return std::string("Error: Invalid level or gender value - ") + e.what();
    }
    catch (const mysqlx::Error& e) {
        return std::string("SQLException: ") + e.what();
    }
    catch (const std::exception& e) {
        return std::string("Exception: ") + e.what();
    }
}

std::optional<std::tuple<int, std::string, std::string>> DatabaseConnector::getCharIdAndMap(int userId, const std::string& charName)
{
    try {
        if (!session) {
            std::cerr << "Session is not initialized." << std::endl;
            return std::nullopt;
        }

        mysqlx::Schema db = session->getSchema("your_database_name");

        // Use the table objects for the two tables
        mysqlx::Table charactersTable = db.getTable("characters_table");
        mysqlx::Table mapsTable = db.getTable("maps");

        std::string query =
            "SELECT c.id, c.current_map, m.gameplay_server_address "
            "FROM characters_table c "
            "LEFT JOIN maps m ON c.current_map = m.name "
            "WHERE c.user_id = ? AND c.character_name = ?";

        mysqlx::SqlStatement stmt = session->sql(query);
        stmt.bind(userId, charName);

        mysqlx::SqlResult result = stmt.execute();
        mysqlx::Row row = result.fetchOne();

        if (row) {
            int charId = row[0].get<int>();
            std::string mapName = row[1].get<std::string>();
            std::string mapAddress = row[2].isNull() ? "" : row[2].get<std::string>();

            return std::make_tuple(charId, mapName, mapAddress);
        }
        else {
            return std::nullopt;
        }
    }
    catch (const mysqlx::Error& e) {
        std::cerr << "MySQL X Error in getCharIdAndMap: " << e.what() << std::endl;
        return std::nullopt;
    }
    catch (const std::exception& e) {
        std::cerr << "Standard Exception in getCharIdAndMap: " << e.what() << std::endl;
        return std::nullopt;
    }
}
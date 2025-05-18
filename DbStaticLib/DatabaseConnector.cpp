// DatabaseConnector.cpp
#include "pch.h"
#include "DatabaseConnector.h"

DatabaseConnector::DatabaseConnector(const std::string& encryptedConfigPath,
    const std::string& key, const std::string& iv) : connection(nullptr), connectedFlag(true) {
    // Initialize MySQL Connector
    driver = get_driver_instance();
    if (!driver) {
        std::cerr << "MySQL driver not found. Exiting." << std::endl;
        std::cout << "MySQL driver not found." << std::endl;
    }

    // Read and decrypt configuration from the encrypted file
    std::ifstream encryptedConfigFile(encryptedConfigPath, std::ios::binary);
    if (encryptedConfigFile.is_open()) {
        std::string encryptedCredentials((std::istreambuf_iterator<char>(encryptedConfigFile)),
            std::istreambuf_iterator<char>());

        std::string decryptedCredentials = decrypt(encryptedCredentials, key);

        if (!decryptedCredentials.empty()) {
            // Now create an istringstream object
            std::cout << "decrypted ini file successfully" << std::endl;
            std::istringstream decryptedStream(decryptedCredentials);
            std::string line;
            //std::cout << decryptedCredentials << "decrypted..." << std::endl;
            while (std::getline(decryptedStream, line)) {
                size_t separatorPos = line.find('=');
                if (separatorPos != std::string::npos) {
                    std::string key = line.substr(0, separatorPos);
                    std::string value = line.substr(separatorPos + 1);

                    key.erase(std::remove_if(key.begin(), key.end(), ::isspace), key.end());
                    value.erase(std::remove_if(value.begin(), value.end(), ::isspace), value.end());
                    std::transform(key.begin(), key.end(), key.begin(), ::tolower);

                    if (key == "address") {
                        address = value;
                    }
                    else if (key == "username") {
                        username = value;
                    }
                    else if (key == "password") {
                        password = value;
                    }
                    else if (key == "sslca") { // assuming you add "sslCa" to your config file
                        sslCa = value;
                    }
                }
            }
        }
        else {
            std::cerr << "Failed to decrypt credentials." << std::endl;
            connectedFlag = false;
        }
        encryptedConfigFile.close();
    }
    else {
        std::cerr << "Failed to open encrypted configuration file." << std::endl;
        connectedFlag = false;
    }
}

void DatabaseConnector::ConnectToDatabase() {
    try {
        sql::ConnectOptionsMap connection_properties;
        connection_properties["hostName"] = address;
        connection_properties["userName"] = username;
        connection_properties["password"] = password;
        connection_properties["schema"] = "users";
        connection_properties["sslCa"] = sslCa; // Add SSL CA certificate path
        connection_properties["sslMode"] = "REQUIRED";

        connection = driver->connect(connection_properties);
        std::cout << "Connected to MySQL accounts database with SSL!" << std::endl;
    }
    catch (sql::SQLException& e) {
        std::cerr << "MySQL Error: " << e.what() << " SQLState: " << e.getSQLState() << std::endl;
        connectedFlag = false;
    }
}

DatabaseConnector::~DatabaseConnector() {
    // Clean up resources
// Ensure proper cleanup in the destructor
    if (connection && !connection->isClosed()) {
        try {
            connection->close();
        }
        catch (sql::SQLException& e) {
            std::cerr << "Error closing MySQL connection: " << e.what() << std::endl;
        }
    }
}

bool DatabaseConnector::IsHealthy() const {
    try {
        if (!connection || connection->isClosed()) {
            return false;
        }

        // A quick query (like SELECT 1)
        std::unique_ptr<sql::Statement> stmt(connection->createStatement());
        stmt->execute("SELECT 1");
        return true;
    }
    catch (const sql::SQLException& e) {
        std::cerr << "IsHealthy failed: " << e.what() << std::endl;
        return false;
    }
}


bool DatabaseConnector::DoesUsernameExist(const std::string& username) {
    try {
        sql::PreparedStatement* pstmt = connection->prepareStatement("SELECT COUNT(*) AS user_count FROM user_table WHERE username = ?");
        pstmt->setString(1, username);

        sql::ResultSet* res = pstmt->executeQuery();

        if (res->next()) {
            int userCount = res->getInt("user_count");
            delete pstmt;
            return (userCount > 0);
        }

        delete pstmt;
    }
    catch (sql::SQLException& e) {
        std::cerr << "MySQL Error: " << e.what() << std::endl;
    }
    // Handle the error appropriately in your application
    return false;
}

bool DatabaseConnector::DoPasswordsMatch(const std::string& username, const std::string& hashedPassword,
    std::string& token, int& userId)
{
    try {
        sql::PreparedStatement* pstmt = connection->prepareStatement("SELECT id, password FROM user_table WHERE username = ?");
        pstmt->setString(1, username);

        sql::ResultSet* res = pstmt->executeQuery();

        if (res->next()) {
            userId = res->getInt("id");
            std::string storedHashedPassword = res->getString("password");

            // Compare the stored hashed password with the provided hashed password
            if (storedHashedPassword == hashedPassword) {
                std::unordered_map<std::string, std::string> claims = {
                    {"username", username},
                    {"userId", std::to_string(userId)}
                };
                token = GenerateToken(claims);
                return true; // Passwords match
            }
        }
    }
    catch (const sql::SQLException& e) {
        std::cerr << "SQL Error: " << e.what() << std::endl;
        // Handle the error appropriately in your application
    }
    userId = -1;  // Return -1 if passwords do not match or an error occurs
    return false;
}

bool DatabaseConnector::RegisterUser(const std::string& username, const std::string& hashedPassword, std::string& token) {
    try {
        sql::PreparedStatement* pstmt = connection->prepareStatement("INSERT INTO user_table (username, password) VALUES (?, ?)");
        pstmt->setString(1, username);
        pstmt->setString(2, hashedPassword);
        pstmt->executeUpdate();
        pstmt = connection->prepareStatement("SELECT LAST_INSERT_ID() AS LastInsertID");
        sql::ResultSet* res = pstmt->executeQuery();

        if (res->next()) {
            int userId = res->getInt("LastInsertID");

            // Registration successful, generate a token
            std::unordered_map<std::string, std::string> claims = {
                {"username", username},
                {"userId", std::to_string(userId)}
            };
            token = GenerateToken(claims);
        }

        delete pstmt;  // Clean up PreparedStatement
        return true;  // Registration successful
    }
    catch (sql::SQLException& e) {
        // Handle the error appropriately in your application
        std::cerr << "Database error: " << e.what() << std::endl;
        return false;  // Registration failure
    }
}

bool DatabaseConnector::GetConnectedFlag()
{
    return connectedFlag;
}

std::string DatabaseConnector::DeleteCharacter(int userId, const std::string& charName)
{
    try {
        std::unique_ptr<sql::PreparedStatement> pstmt(
            connection->prepareStatement(
                "DELETE FROM characters_table WHERE user_id = ? AND character_name = ?"
            )
        );
        pstmt->setInt(1, userId);
        pstmt->setString(2, charName);

        int affectedRows = pstmt->executeUpdate();
        if (affectedRows > 0) {
            return "CHARACTER_DELETED";
        }
        else {
            return "CHARACTER_NOT_FOUND";
        }
    }
    catch (sql::SQLException& e) {
        std::cerr << "SQL Error while deleting character: " << e.what() << std::endl;
        return "DATABASE_ERROR";
    }
}

std::string DatabaseConnector::GetCharactersInfoByUserId(int userId) // only for login pages
{
    std::string charactersInfo;

    try {
        // Your SQL query to retrieve characters' info based on the user's ID
        std::string query = "SELECT character_name, level, gender, appearance FROM characters_table WHERE user_id = ?";

        // Prepare and execute the query
        sql::PreparedStatement* preparedStatement = connection->prepareStatement(query);
        preparedStatement->setInt(1, userId);
        sql::ResultSet* resultSet = preparedStatement->executeQuery();

        // Process the result set and construct the characters' info string
        while (resultSet->next()) {
            std::string characterName = resultSet->getString("character_name");
            std::string level = resultSet->getString("level");
            std::string gender = resultSet->getString("gender");
            std::string appearance = resultSet->getString("appearance");

            // Construct the characters' info string as needed
            charactersInfo += characterName + "|" + level + "|" + gender + "|" + appearance + "|";
        }

        // Cleanup
        delete preparedStatement;
        delete resultSet;
    }
    catch (sql::SQLException& e) {
        // Handle the error appropriately in your application
        std::cerr << "Database error: " << e.what() << std::endl;
        charactersInfo = "db_err";
    }

    // If charactersInfo is still empty, no characters were found
    if (charactersInfo.empty()) {
        charactersInfo = "EMPTY";
    }

    return charactersInfo;
}

std::string DatabaseConnector::DoesCharacterNameExist(const std::string& charName)
{
    std::string o_returnMsg = "";
    //std::cout << "about to send a checkname command to db" << std::endl;
    try {
        sql::PreparedStatement* pstmt = connection->prepareStatement("SELECT COUNT(*) FROM characters_table WHERE character_name=?");
        pstmt->setString(1, charName);
        sql::ResultSet* res = pstmt->executeQuery();
        res->next();
        bool exists = res->getInt(1) > 0;
        if (exists)
            o_returnMsg = "exists";
        else o_returnMsg = "available";
        delete res;
        delete pstmt;
        return o_returnMsg;
    }
    catch (sql::SQLException& e) {
        std::cerr << "SQLException in DatabaseConnector::DoesCharacterNameExist: " << e.what() << std::endl;
        return std::string("Database error: ") + e.what();
    }
}

std::string DatabaseConnector::AddCosmeticCharDataToDB(const int userId, const std::string& charData) {
    std::string characterName, levelStr, genderStr, appearance, editableCharData;
    int level, gender, userid;

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

        std::cout << "[DEBUG] Raw charData input: [" << charData << "]" << std::endl;
        // Convert level and gender to integers
        level = std::stoi(levelStr);

        // Prepare the SQL statement
        std::unique_ptr<sql::PreparedStatement> pstmt(
            connection->prepareStatement(
                "INSERT INTO characters_table (user_id, character_name, level, gender, appearance) VALUES (?, ?, ?, ?, ?)"
            )
        );

        // Bind the values to the SQL statement
        pstmt->setInt(1, userId);
        pstmt->setString(2, characterName);
        pstmt->setInt(3, level);
        pstmt->setInt(4, gender);
        pstmt->setString(5, appearance);

        std::cout << "**Trying to execute insert db command**" << std::endl;

        // Execute the SQL statement
        pstmt->executeUpdate();

        return "success";
    }
    catch (const std::invalid_argument& e) {
        return std::string("Error: Invalid level or gender value - ") + e.what();
    }
    catch (const sql::SQLException& e) {
        return std::string("SQLException: ") + e.what();
    }
    catch (const std::exception& e) {
        return std::string("Exception: ") + e.what();
    }
}

std::optional<std::tuple<int, std::string, std::string>> DatabaseConnector::getCharIdAndMap(int userId, const std::string& charName)
{
    try {
        sql::PreparedStatement* pstmt = connection->prepareStatement(
            "SELECT c.id, c.current_map, m.gameplay_server_address "
            "FROM characters_table c "
            "LEFT JOIN maps m ON c.current_map = m.name "
            "WHERE c.user_id = ? AND c.character_name = ?");

        pstmt->setInt(1, userId);
        pstmt->setString(2, charName);

        sql::ResultSet* res = pstmt->executeQuery();

        if (res->next()) {
            int charId = res->getInt("id");
            std::string mapName = res->getString("current_map");
            std::string mapAddress = res->isNull("gameplay_server_address") ?
                "" : res->getString("gameplay_server_address");

            return std::make_tuple(charId, mapName, mapAddress);
        }
        else {
            return std::nullopt;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error in getCharIdMapAndAddress: " << e.what() << std::endl;
        return std::nullopt;
    }
}


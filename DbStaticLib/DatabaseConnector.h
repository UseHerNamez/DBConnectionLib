// DatabaseConnector.h
#pragma once

#include <driver.h>
#include <connection.h>
#include <exception.h>
#include <iostream>
#include <fstream>
#include <string>
#include "EncryptionUtils.h"
#include <sstream>
#include <resultset.h>
#include <optional>
#include <prepared_statement.h>

class DatabaseConnector {
public:
    DatabaseConnector(const std::string& encryptedConfigPath, const std::string& key, const std::string& iv);
    ~DatabaseConnector();

    void ConnectToDatabase();
    bool DoesUsernameExist(const std::string& username);
    bool DoPasswordsMatch(const std::string& username, const std::string& password, std::string& token, int& userId);
    bool RegisterUser(const std::string& username, const std::string& hashedPassword, std::string& token);
    bool GetConnectedFlag();
    std::string DeleteCharacter(int userId, const std::string& charName);
    std::string GetCharactersInfoByUserId(int userId);
    std::string DoesCharacterNameExist(const std::string& charName);
    std::string AddCosmeticCharDataToDB(const int userId, const std::string& charData);
    std::optional<std::tuple<int, std::string, std::string>> getCharIdAndMap
    (int userId, const std::string& charName);
    bool IsHealthy() const;

private:
    sql::Driver* driver;
    sql::Connection* connection;
    std::string address;
    std::string username;
    std::string password;
    std::string sslCa;
    bool connectedFlag;
};


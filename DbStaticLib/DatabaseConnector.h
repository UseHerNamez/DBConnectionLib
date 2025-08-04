#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <optional>
#include <sstream>
#include <memory>
#include <mysqlx/xdevapi.h>
#include "EncryptionUtils.h"

class DatabaseConnector {
public:
    explicit DatabaseConnector(std::shared_ptr<mysqlx::Session> i_session);
    //DatabaseConnector(const std::string& encryptedConfigPath, const std::string& key, const std::string& iv);
    ~DatabaseConnector();

    bool DoesUsernameExist(const std::string& username);
    bool DoPasswordsMatch(const std::string& username, const std::string& password, std::string& token, int& userId);
    bool RegisterUser(const std::string& username, const std::string& hashedPassword, std::string& token);
    bool GetConnectedFlag();
    std::string DeleteCharacter(int userId, const std::string& charName);
    std::string GetCharactersInfoByUserId(int userId);
    std::string DoesCharacterNameExist(const std::string& charName);
    std::string AddCosmeticCharDataToDB(const int userId, const std::string& charData);
    std::optional<std::tuple<int, std::string, std::string>> getCharIdAndMap(int userId, const std::string& charName);
    bool IsHealthy() const;
    std::shared_ptr<mysqlx::Session> GetSession() const { return session; }

private:
    std::shared_ptr<mysqlx::Session> session;
    bool connectedFlag = true;
};

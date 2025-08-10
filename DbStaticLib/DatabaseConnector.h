#pragma once

#include <memory>
#include <optional>
#include <string>
#include <tuple>

// Forward declare inside the correct inline namespaces
namespace mysqlx { inline namespace abi2 { inline namespace r0 { class Session; } } }

class DatabaseConnector {
public:
    explicit DatabaseConnector(std::shared_ptr<mysqlx::Session> s);
    ~DatabaseConnector();

    bool DoesUsernameExist(const std::string& username);
    bool DoPasswordsMatch(const std::string& username,
        const std::string& hashedPassword,
        std::string& token,
        int& userId);
    bool RegisterUser(const std::string& username,
        const std::string& hashedPassword,
        std::string& token);

    bool GetConnectedFlag() const;
    std::string DeleteCharacter(int userId, const std::string& charName);
    std::string GetCharactersInfoByUserId(int userId);
    std::string DoesCharacterNameExist(const std::string& charName);
    std::string AddCosmeticCharDataToDB(int userId, const std::string& charData);

    std::optional<std::tuple<int, std::string, std::string>>
        getCharIdAndMap(int userId, const std::string& charName);

    bool IsHealthy() const;

    std::shared_ptr<mysqlx::Session> GetSession() const { return session; }

private:
    std::shared_ptr<mysqlx::Session> session;
    bool connectedFlag = true;
};

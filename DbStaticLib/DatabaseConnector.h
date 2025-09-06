#pragma once

#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <map>

// Forward declare inside the correct inline namespaces
namespace mysqlx { inline namespace abi2 { inline namespace r0 { class Session; } } }

class DatabaseConnector {
public:
    explicit DatabaseConnector(std::shared_ptr<mysqlx::Session> s);
    ~DatabaseConnector();

    // Login related operations
    bool DoesUsernameExist(const std::string& username);
    bool DoPasswordsMatch(const std::string& username,
        const std::string& hashedPassword,
        std::string& token,
        int& userId);
    bool RegisterUser(const std::string& username,
        const std::string& hashedPassword,
        std::string& token);
    std::string DeleteCharacter(int userId, const std::string& charName);
    std::string GetCharactersInfoByUserId(int userId);
    std::string DoesCharacterNameExist(const std::string& charName);
    std::string AddCosmeticCharDataToDB(int userId, const std::string& charData);
    std::optional<std::tuple<int, std::string, std::string>>
        getCharIdAndMap(int userId, const std::string& charName);

    // Gameplay maps related operations
    std::optional<std::tuple<std::string, std::string, int, std::string,
        int, int, int, int, int, int>>GetCharGameplayDataById(int charId);
    std::string GetLastError() const;
    bool UpdateCharacterStat(int CharId, const std::string& StatName, int Value);
    bool UpdateCharacterStats(int CharId, const std::map<std::string, int>& Stats);


    // Connection related operations
    bool IsHealthy() const;
    bool GetConnectedFlag() const;
    std::shared_ptr<mysqlx::Session> GetSession() const { return session; }

private:
    std::shared_ptr<mysqlx::Session> session;
    bool connectedFlag = true;
    mutable std::string lastError_;
};

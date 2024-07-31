#include <SDL2/SDL.h>
#include <SDL2/SDL_image.h>

#include <SDL_ttf.h>
#include <iostream>
#include <memory>//For smart pointers.
#include <map>//For associative containers.
#include <string>
#include <sodium.h>//For cryptographic operations (Argon2 hashing).
#include <sqlite3.h>//For SQLite database operations.


#include <random>//For generating random numbers 
#include <ctime>//For handling time-related functions.
#include <regex>//For regular expressions.
#include <cmath>

//Boost.Beast sends the JSON data via an HTTPS request to Sendinblue's API.and then Sendinblue processes the request and delivers the message.
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
//rapidjson Used to format and parse the message data into JSON, which is required by the Sendinblue API.
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

#include <cstdlib>  // For std::getenv

using namespace std;

// Forward declaration of all of the base classes
class State;
class User;
class Verification;
class NavigationMenu;
// Enumeration of states
enum AppState {
    SPLASH_SCREEN,
    LOGIN_SCREEN,
    SIGNUP_SCREEN,
    MAIN_DASHBOARD,
    S_VERIFICATION_SCREEN,
    PASSWORD_RESET_SCREEN,
    HELP_SCREEN,
    F_VERIFICATION_SCREEN,
    PROFILE_SCREEN,
    SETTINGS_SCREEN,
    COGNITIVE_STATS_SCREEN,
    DATA_STATS_SCREEN,
    TARGETS_SCREEN,
    SYSTEM_HEALTH_SCREEN
};


// Screen names corresponding to State
const char* screenNames[] = {
    "Splash Screen",
    "Login Screen",
    "Signup Screen",
    "Main Dashboard Screen",
    "S Verification Screen",
    "Password Reset  Screen",
    "Help Screen",
    "F Verification Screen",
"Profile Screen",
"Settings Screen",
"Cognitive Stats Scren",
"Data Stats Screen",
"Targets Screen",
"System Health Screen"


};

// Globals
int Width = 800;
int Height = 600;

SDL_Window* window = nullptr;
SDL_Renderer* renderer = nullptr;
TTF_Font* digitalFont = nullptr;
std::unique_ptr<User> currentUser = nullptr;
AppState currentState = SPLASH_SCREEN;
std::unique_ptr<State> currentStateInstance;
Uint32 startTime = 0;

void changeState(AppState newState);
//keep in mind GVCode (Generated Verification Code) and verificationCode (User-entered Code)

SDL_Texture* loadTexture(const std::string &path, SDL_Renderer *renderer) {
    SDL_Texture* newTexture = nullptr;
    SDL_Surface* loadedSurface = IMG_Load(path.c_str());
    if (loadedSurface == nullptr) {
        std::cerr << "Unable to load image " << path << "! SDL_image Error: " << IMG_GetError() << std::endl;
    } else {
        newTexture = SDL_CreateTextureFromSurface(renderer, loadedSurface);
        if (newTexture == nullptr) {
            std::cerr << "Unable to create texture from " << path << "! SDL Error: " << SDL_GetError() << std::endl;
        }
        SDL_FreeSurface(loadedSurface);
    }
    return newTexture;
}
int radius = 15;
void renderRoundedRect(SDL_Renderer* renderer, int x, int y, int w, int h, int radius, SDL_Color color) {
    SDL_SetRenderDrawColor(renderer, color.r, color.g, color.b, color.a);
    
    // Draw the four corners as circles
    for (int i = 0; i <= radius; i++) {
        for (int j = 0; j <= radius; j++) {
            if (i * i + j * j <= radius * radius) {
                SDL_RenderDrawPoint(renderer, x + radius - i, y + radius - j);
                SDL_RenderDrawPoint(renderer, x + w - radius + i, y + radius - j);
                SDL_RenderDrawPoint(renderer, x + radius - i, y + h - radius + j);
                SDL_RenderDrawPoint(renderer, x + w - radius + i, y + h - radius + j);
            }
        }
    }

    // Draw the sides as rectangles
    SDL_Rect top = { x + radius, y, w - 2 * radius, radius };
    SDL_Rect bottom = { x + radius, y + h - radius, w - 2 * radius, radius };
    SDL_Rect left = { x, y + radius, radius, h - 2 * radius };
    SDL_Rect right = { x + w - radius, y + radius, radius, h - 2 * radius };
    SDL_Rect center = { x + radius, y + radius, w - 2 * radius, h - 2 * radius };

    SDL_RenderFillRect(renderer, &top);
    SDL_RenderFillRect(renderer, &bottom);
    SDL_RenderFillRect(renderer, &left);
    SDL_RenderFillRect(renderer, &right);
    SDL_RenderFillRect(renderer, &center);
}


class User {
private:
    std::string emailAddress;
    std::string username;
    std::string password;

public:
    User(const std::string& userEmail, const std::string& userName, const std::string& pass)
        : emailAddress(userEmail), username(userName), password(pass) {}

    // Getters and setters as needed
    std::string getEmailAddress() const { return emailAddress; }
    std::string getUsername() const { return username; }
    std::string getPassword() const { return password; }
};

// Function to render text
void renderText(const std::string& message, int x, int y, SDL_Color color, TTF_Font* font, SDL_Renderer* renderer) {
    SDL_Surface* surface = TTF_RenderText_Blended(font, message.c_str(), color);
    SDL_Texture* texture = SDL_CreateTextureFromSurface(renderer, surface);
    SDL_Rect rect = { x, y, surface->w, surface->h };
    SDL_RenderCopy(renderer, texture, nullptr, &rect);
    SDL_FreeSurface(surface);
    SDL_DestroyTexture(texture);
}

// Global variables

std::string apiKey;  // Store the API key

 std::string getApiKey()  {
        const char* apiKeyEnv = std::getenv("SENDINBLUE_API_KEY");
        if (apiKeyEnv) {
            return std::string(apiKeyEnv);
        } else {
            std::cerr << "Environment variable SENDINBLUE_API_KEY not set." << std::endl;
            return "";
        }
    };//Neurabyte_AccountVerification_Key
    
sqlite3* db = nullptr;


bool initializeDatabase(const std::string& dbName) {
    if (sqlite3_open(dbName.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Error opening SQLite database: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    // Create users table
    const char* createUsersTableSQL = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            emailAddress TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        );
    )";

    char* errorMessage = nullptr;
    if (sqlite3_exec(db, createUsersTableSQL, nullptr, nullptr, &errorMessage) != SQLITE_OK) {
        std::cerr << "SQL error creating users table: " << errorMessage << std::endl;
        sqlite3_free(errorMessage);
        return false;
    }

    // Create verification_codes table
    const char* createVerificationCodesTableSQL = R"(
        CREATE TABLE IF NOT EXISTS verification_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            phone_number TEXT,
            GVCode TEXT NOT NULL,
            expiration_time INTEGER NOT NULL,
            CHECK (email IS NOT NULL OR phone_number IS NOT NULL),
            CHECK (email IS NULL OR phone_number IS NULL)
        );
    )";

    if (sqlite3_exec(db, createVerificationCodesTableSQL, nullptr, nullptr, &errorMessage) != SQLITE_OK) {
        std::cerr << "SQL error creating verification_codes table: " << errorMessage << std::endl;
        sqlite3_free(errorMessage);
        return false;
    }

    return true;
}


std::string hashPassword(const std::string& password) {
    const char *password_cstr = password.c_str();
    char hash[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(hash, password_cstr, strlen(password_cstr), 
        crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE) != 0) {
        // Out of memory, handle error appropriately
        std::cerr << "Error hashing password." << std::endl;
        return "";
    }
    return std::string(hash);
}













bool insertUser(const User &user);
void setCurrentUser(const std::string &emailAddress, const std::string &username, const std::string &hashedPassword);
bool emailExists(const std::string &emailAddress);


void CreateUser(const std::string& username, const std::string& emailAddress, const std::string& password) {
    // Validate user data (this step is simplified; in real applications, you should perform thorough validation)
    if (username.empty() || emailAddress.empty() || password.empty()) {
        std::cerr << "Error: All fields are required." << std::endl;
        return;
    }
// Check if the email address already exists
    if (emailExists(emailAddress)) {
        std::cerr << "Error: Email address already exists." << std::endl;
        return;
    }
    // Hash the user's password
    std::string hashedPassword = hashPassword(password);

    // Create a User object
    User newUser(emailAddress, username, hashedPassword);

    // Save the new user to the database
    if (!insertUser(newUser)) {
        std::cerr << "Error: Failed to save user to database." << std::endl;
    }else {
        std::cout << "User created successfully." << std::endl;
   // Set the current user
        setCurrentUser(emailAddress, username, hashedPassword);
    }
}
bool insertUser(const User& user) {
    const char* insertSQL = "INSERT INTO users (emailAddress, username, password) VALUES (?, ?, ?)";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, insertSQL, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    if (sqlite3_bind_text(stmt, 1, user.getEmailAddress().c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 2, user.getUsername().c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 3, user.getPassword().c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        std::cerr << "Failed to bind parameters: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

void setCurrentUser(const std::string& emailAddress, const std::string& username, const std::string& hashedPassword) {
    currentUser = std::make_unique<User>(emailAddress, username, hashedPassword);
}

bool emailExists(const std::string& emailAddress) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    const char* sql = "SELECT COUNT(*) FROM users WHERE emailAddress = ?";

    // Open the database
    if (sqlite3_open("C:/NEW/neurabyte.db", &db) != SQLITE_OK) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return true; // Assume email exists to prevent further errors
    }

    // Prepare the SQL statement
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return true; // Assume email exists to prevent further errors
    }

    // Bind the parameter
    sqlite3_bind_text(stmt, 1, emailAddress.c_str(), -1, SQLITE_STATIC);

    // Execute the statement
    int result = sqlite3_step(stmt);
    bool exists = (result == SQLITE_ROW && sqlite3_column_int(stmt, 0) > 0);

    // Finalize the statement and close the database
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return exists;
}



bool validateLogin(const std::string& username, const std::string& password) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    const char* sql = "SELECT username, password FROM users WHERE username = ?";

    // Open the database
    if (sqlite3_open("C:/NEW/neurabyte.db", &db) != SQLITE_OK) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    // Prepare the SQL statement
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return false;
    }

    // Bind the username parameter
    if (sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC) != SQLITE_OK) {
        std::cerr << "Failed to bind parameter: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    // Execute the statement and check if a row was returned
    int result = sqlite3_step(stmt);
    if (result == SQLITE_ROW) {
        // Retrieve the username and hashed password from the database
        std::string dbUsername = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        std::string hashedPassword = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));

        // Verify the username and password using libsodium's function
        if (dbUsername == username && crypto_pwhash_str_verify(hashedPassword.c_str(), password.c_str(), password.length()) == 0) {
            // Username and password match, login successful
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return true;
        }
    }

    // Finalize and close database
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    // If execution reaches here, login failed
    return false;
}
// Function to detect if the input is an email
bool isEmail(const std::string& input) {
    const std::regex pattern("[\\w.%+-]+@[\\w.-]+\\.[a-zA-Z]{2,}");
    return std::regex_match(input, pattern);
}








// Function to generate a random verification code
std::string generateVerificationCode() {
    static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const int codeLength = 6;
    std::string code;
    code.resize(codeLength);

    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, sizeof(alphanum) - 2);

    for (int i = 0; i < codeLength; ++i) {
        code[i] = alphanum[distribution(generator)];
    }
    return code;
}

// Function to store the verification code and its expiration time in the SQLite database
void storeEmailCodeInDatabase(const std::string& emailAddress, const std::string& GVCode) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    std::string sql = "INSERT INTO verification_codes (email, code, expiration_time) VALUES (?, ?, ?);";
    
    // Open database
    if (sqlite3_open("C:/NEW/neurabyte.db", &db) != SQLITE_OK) {
        std::cerr << "Failed to open database: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    // Prepare SQL statement
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return;
    }

    // Set parameters
    sqlite3_bind_text(stmt, 1, emailAddress.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, GVCode.c_str(), -1, SQLITE_STATIC);

    // Set expiration time to 10 minutes from now
    std::time_t expirationTime = std::time(nullptr) + 600; // 600 seconds = 10 minutes
    sqlite3_bind_int(stmt, 3, expirationTime);

    // Execute statement
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db) << std::endl;
    }

    // Clean up
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}




std::string sendVerificationCodeToEmail(const std::string& emailAddress) {
    std::string apiKey;
    std::string GVCode;

    try {
        apiKey = getApiKey(); // Fetch the API key for Sendinblue
      
    } catch (const std::exception& e) {
        std::cerr << "Failed to get API key: " << e.what() << std::endl;
        return "";
    }
 if (apiKey.empty()) {
        std::cerr << "API key is empty." << std::endl;
        return "";
    }



    try {
        GVCode = generateVerificationCode(); // Generate a verification code
    } catch (const std::exception& e) {
        std::cerr << "Failed to generate verification code: " << e.what() << std::endl;
        return "";
    }

    try {
        storeEmailCodeInDatabase(emailAddress, GVCode); // Store the email and code in your database
    } catch (const std::exception& e) {
        std::cerr << "Failed to store email code in database: " << e.what() << std::endl;
        return "";
    }

    std::string emailContent = "Your verification code is: " + GVCode;
 std::cout << "your email content is  " << emailContent<< std::endl;
    try {
        boost::asio::io_context io_context;
        boost::asio::ssl::context ssl_context(boost::asio::ssl::context::tlsv12_client);

        boost::asio::ip::tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve("api.sendinblue.com", "443");

        boost::asio::ip::tcp::socket socket(io_context);
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket(std::move(socket), ssl_context);

        try {
            boost::asio::connect(ssl_socket.lowest_layer(), endpoints);
        } catch (const std::exception& e) {
            std::cerr << "Failed to connect: " << e.what() << std::endl;
            return "";
        }
 
        try {
            ssl_socket.handshake(boost::asio::ssl::stream_base::client);
        } catch (const std::exception& e) {
            std::cerr << "Failed to perform SSL handshake: " << e.what() << std::endl;
            return "";
        }

        boost::beast::http::request<boost::beast::http::string_body> req{
            boost::beast::http::verb::post, "/v3/smtp/email", 11
        };
        req.set(boost::beast::http::field::host, "api.sendinblue.com");
        req.set(boost::beast::http::field::authorization, "api-key " + apiKey);
        req.set(boost::beast::http::field::content_type, "application/json");
req.set(boost::beast::http::field::connection, "keep-alive");
req.set(boost::beast::http::field::accept_encoding, "gzip, deflate, br");
req.set(boost::beast::http::field::accept, "*/*");
req.set(boost::beast::http::field::user_agent, "Neurabyte/1.0");

 


        rapidjson::Document document;
        document.SetObject();
        rapidjson::Document::AllocatorType& allocator = document.GetAllocator();

        rapidjson::Value sender(rapidjson::kObjectType);
        sender.AddMember("email", "siddiqaa954@gmail.com", allocator);
        sender.AddMember("name", "Neurabyte", allocator);

        rapidjson::Value recipient(rapidjson::kObjectType);
        recipient.AddMember("email", rapidjson::Value().SetString(emailAddress.c_str(), allocator), allocator);

        rapidjson::Value to(rapidjson::kArrayType);
        to.PushBack(recipient, allocator);

        rapidjson::Value content(rapidjson::kArrayType);
        rapidjson::Value contentObj(rapidjson::kObjectType);
        contentObj.AddMember("type", "text/plain", allocator);
        contentObj.AddMember("value", rapidjson::Value().SetString(emailContent.c_str(), allocator), allocator);
        content.PushBack(contentObj, allocator);

        document.AddMember("sender", sender, allocator);
        document.AddMember("to", to, allocator);
        document.AddMember("subject", "Verification Code", allocator);
        document.AddMember("htmlContent", rapidjson::Value().SetString(emailContent.c_str(), allocator), allocator);

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        document.Accept(writer);

        req.body() = buffer.GetString();
        req.prepare_payload();
 
        try {
            boost::beast::http::write(ssl_socket, req);
        } catch (const std::exception& e) {
            std::cerr << "Failed to send HTTP request: " << e.what() << std::endl;
            return "";
        }

        boost::beast::flat_buffer responseBuffer;
        boost::beast::http::response<boost::beast::http::string_body> res;

        try {
            boost::beast::http::read(ssl_socket, responseBuffer, res);
        } catch (const std::exception& e) {
            std::cerr << "Failed to read HTTP response: " << e.what() << std::endl;
            return "";
        }
              std::cout << "API Key: " << apiKey << std::endl;
        if (res.result() == boost::beast::http::status::unauthorized) {
            std::cerr << "Error: Unauthorized access. Please check your API key." << std::endl;
        } else if (res.result() == boost::beast::http::status::forbidden) {
            std::cerr << "Error: Forbidden. The token is invalid or expired." << std::endl;
        } else if (res.result() != boost::beast::http::status::ok) {
            std::cerr << "Error: " << res.result() << " " << res.reason() << std::endl;
        } else {
            std::cout << "Response: " << res.body() << std::endl;
        }
// Close the SSL socket and underlying TCP socket

      try {
    // Perform SSL shutdown
    ssl_socket.shutdown(); // No arguments are needed here
} catch (const std::exception& e) {
    std::cerr << "Failed to shut down SSL socket: " << e.what() << std::endl;
}

try {
    // Shutdown the underlying TCP socket
    ssl_socket.lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both);
} catch (const std::exception& e) {
    std::cerr << "Failed to shut down TCP socket: " << e.what() << std::endl;
}

try {
    // Close the underlying TCP socket
    ssl_socket.lowest_layer().close();
} catch (const std::exception& e) {
    std::cerr << "Failed to close TCP socket: " << e.what() << std::endl;
}




    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return GVCode;
}




// Hypothetical Twilio wrapper

void storePhoneCodeInDatabase(const std::string& phoneNumber, const std::string& GVCode) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    std::string sql = "INSERT INTO verification_codes (phone_number, code, expiration_time) VALUES (?, ?, ?);";
    
    // Open database
    if (sqlite3_open("C:/NEW/neurabyte.db", &db) != SQLITE_OK) {
        std::cerr << "Failed to open database: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    // Prepare SQL statement
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return;
    }

    // Set parameters
    sqlite3_bind_text(stmt, 1, phoneNumber.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, GVCode.c_str(), -1, SQLITE_STATIC);

    // Set expiration time to 10 minutes from now
    std::time_t expirationTime = std::time(nullptr) + 600; // 600 seconds = 10 minutes
    sqlite3_bind_int(stmt, 3, expirationTime);

    // Execute statement
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db) << std::endl;
    }

    // Clean up
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

std::string sendVerificationCodeToPhone(const std::string& phoneNumber) {
    std::string apiKey, GVCode;

    try {
        apiKey = getApiKey();
    } catch (const std::exception& e) {
        std::cerr << "Failed to get API key: " << e.what() << std::endl;
        return "";
    }

    try {
        GVCode = generateVerificationCode();
    } catch (const std::exception& e) {
        std::cerr << "Failed to generate verification code: " << e.what() << std::endl;
        return "";
    }

    try {
        storePhoneCodeInDatabase(phoneNumber, GVCode);
    } catch (const std::exception& e) {
        std::cerr << "Failed to store phone code in database: " << e.what() << std::endl;
        return "";
    }

    std::string smsContent = "Your verification code is: " + GVCode;

    try {
        boost::asio::io_context io_context;
        boost::asio::ssl::context ssl_context(boost::asio::ssl::context::tlsv12_client);

        try {
            boost::asio::ip::tcp::resolver resolver(io_context);
            auto endpoints = resolver.resolve("api.sendinblue.com", "443");
            boost::asio::ip::tcp::socket socket(io_context);
            boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket(std::move(socket), ssl_context);

            try {
                boost::asio::connect(ssl_socket.lowest_layer(), endpoints);
            } catch (const std::exception& e) {
                std::cerr << "Failed to connect: " << e.what() << std::endl;
                return "";
            }

            try {
                ssl_socket.handshake(boost::asio::ssl::stream_base::client);
            } catch (const std::exception& e) {
                std::cerr << "Failed to perform SSL handshake: " << e.what() << std::endl;
                return "";
            }

            boost::beast::http::request<boost::beast::http::string_body> req{boost::beast::http::verb::post, "/v3/transactionalSMS/sms", 11};
            req.set(boost::beast::http::field::host, "api.sendinblue.com");
            req.set(boost::beast::http::field::authorization, "Bearer " + apiKey);
            req.set(boost::beast::http::field::content_type, "application/json");
req.set(boost::beast::http::field::connection, "keep-alive");
req.set(boost::beast::http::field::accept_encoding, "gzip, deflate, br");
req.set(boost::beast::http::field::accept, "*/*");
req.set(boost::beast::http::field::user_agent, "Neurabyte/1.0");
            rapidjson::Document document;
            document.SetObject();
            rapidjson::Document::AllocatorType& allocator = document.GetAllocator();

            document.AddMember("sender", rapidjson::Value().SetString("Neurabyte", allocator), allocator);
            document.AddMember("recipient", rapidjson::Value().SetString(phoneNumber.c_str(), allocator), allocator);
            document.AddMember("content", rapidjson::Value().SetString(smsContent.c_str(), allocator), allocator);

            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            document.Accept(writer);

            req.body() = buffer.GetString();
            req.prepare_payload();

            try {
                boost::beast::http::write(ssl_socket, req);
            } catch (const std::exception& e) {
                std::cerr << "Failed to send HTTP request: " << e.what() << std::endl;
                return "";
            }

            boost::beast::flat_buffer responseBuffer;
            boost::beast::http::response<boost::beast::http::string_body> res;

            try {
                boost::beast::http::read(ssl_socket, responseBuffer, res);
            } catch (const std::exception& e) {
                std::cerr << "Failed to read HTTP response: " << e.what() << std::endl;
                return "";
            }

            std::cout << "Response: " << res.body() << std::endl;
try {
    // Perform SSL shutdown
    ssl_socket.shutdown(); // No arguments are needed here
} catch (const std::exception& e) {
    std::cerr << "Failed to shut down SSL socket: " << e.what() << std::endl;
}

try {
    // Shutdown the underlying TCP socket
    ssl_socket.lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both);
} catch (const std::exception& e) {
    std::cerr << "Failed to shut down TCP socket: " << e.what() << std::endl;
}

try {
    // Close the underlying TCP socket
    ssl_socket.lowest_layer().close();
} catch (const std::exception& e) {
    std::cerr << "Failed to close TCP socket: " << e.what() << std::endl;
}



        } catch (const std::exception& e) {
            std::cerr << "Failed to set up SSL connection: " << e.what() << std::endl;
            return "";
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return "";
    }

    return GVCode;
}

 bool validateVerificationCode(const std::string& verificationCode, const std::string& GVCode) {
    sqlite3* db;
    sqlite3_stmt* stmt;


    //std::string sql = "SELECT GVCode FROM verification_codes WHERE (email = ? OR phone_number = ?) AND expiration_time > ?;";
 std::string sql;
    if (isEmail) {
        sql = "SELECT expiration_time FROM verification_codes WHERE email = ? AND GVCode = ?";
    } else {
        sql = "SELECT expiration_time FROM verification_codes WHERE phone_number = ? AND GVCode = ?";
    }




    try {
        if (sqlite3_open("C:/NEW/neurabyte.db", &db) != SQLITE_OK) {
            std::cerr << "Failed to open database: " << sqlite3_errmsg(db) << std::endl;
            return false;
        }

        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
            sqlite3_close(db);
            return false;
        }

        if (sqlite3_bind_text(stmt, 1, verificationCode.c_str(), -1, SQLITE_STATIC) != SQLITE_OK) {
            std::cerr << "Failed to bind parameter 1: " << sqlite3_errmsg(db) << std::endl;
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return false;
        }

        if (sqlite3_bind_text(stmt, 2, verificationCode.c_str(), -1, SQLITE_STATIC) != SQLITE_OK) {
            std::cerr << "Failed to bind parameter 2: " << sqlite3_errmsg(db) << std::endl;
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return false;
        }

        std::time_t currentTime = std::time(nullptr);
        if (sqlite3_bind_int(stmt, 3, static_cast<int>(currentTime)) != SQLITE_OK) {
            std::cerr << "Failed to bind current time: " << sqlite3_errmsg(db) << std::endl;
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return false;
        }

        bool isValid = false;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string storedCode(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
            if (GVCode == storedCode) {
                isValid = true;
            }
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);

        return isValid;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        if (stmt) sqlite3_finalize(stmt);
        if (db) sqlite3_close(db);
        return false;
    }
}


// Function to check if the verification code has expired
bool checkCodeExpiration(const std::string& verificationCode) {
    sqlite3* db = nullptr;
    sqlite3_stmt* stmt = nullptr;
    std::string sql = "SELECT expiration_time FROM verification_codes WHERE GVCode = ?;";

    try {
        // Open database
        if (sqlite3_open("C:/NEW/neurabyte.db", &db) != SQLITE_OK) {
            std::cerr << "Failed to open database: " << sqlite3_errmsg(db) << std::endl;
            return false;
        }

        // Prepare SQL statement
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
            sqlite3_close(db);
            return false;
        }

        // Set parameter
        if (sqlite3_bind_text(stmt, 1, verificationCode.c_str(), -1, SQLITE_STATIC) != SQLITE_OK) {
            std::cerr << "Failed to bind parameter: " << sqlite3_errmsg(db) << std::endl;
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return false;
        }

        // Execute statement and check expiration
        bool isExpired = false;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            std::time_t expirationTime = sqlite3_column_int(stmt, 0);
            if (std::time(nullptr) > expirationTime) {
                isExpired = true;
            }
        }

        // Clean up
        sqlite3_finalize(stmt);
        sqlite3_close(db);

        return isExpired;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        if (stmt) sqlite3_finalize(stmt);
        if (db) sqlite3_close(db);
        return false;
    }
}



















// Abstract class State
class State {
public:
    SDL_Window* window;
    SDL_Renderer* renderer;
    TTF_Font* digitalFont;

    State(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* digitalFont)
        : window(window), renderer(renderer), digitalFont(digitalFont) {}
    virtual void handleEvents(SDL_Event& event) = 0;
    virtual void update() = 0;
    virtual void render(){
    };
    virtual void cleanup() = 0;  // Pure virtual function
    virtual ~State() = default;
     
};


// SplashScreenState class
class SplashScreenState : public State {
public:
    SplashScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* digitalFont):State(window ,renderer, digitalFont ) {
        // Initialization if needed
    }
    
    void handleEvents(SDL_Event& event) override {
        // Handle events specific to Splash Screen
    }
    
    void update() override {
        Uint32 currentTime = SDL_GetTicks();
        if (currentTime - startTime > 1000) { // Splash screen duration: 5 seconds
            changeState(LOGIN_SCREEN);
        }
    }
    
    void render() override {
        
        
      



        SDL_Color white = { 255, 255, 255, 255 };
// Get the dimensions of the text
    int textWidth, textHeight;
    TTF_SizeText(digitalFont, "NEURABYTE", &textWidth, &textHeight);


int textX = (Width-textWidth) / 2; // Center horizontally
    int textY = (Height-textHeight )/ 2; // Center vertically

        renderText("NEURABYTE",  textX, textY, white, digitalFont, renderer);
    }
void cleanup() override {
        // Implement cleanup logic 
    }

};




















//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



// LoginScreenState class
class LoginScreenState : public State {
private:
    std::string loginMessage;  
    SDL_Color loginMessageColor;  
     Uint32 loginMessageTime;  
    const Uint32 LOGIN_MESSAGE_DISPLAY_TIME = 2000;  // 2000 milliseconds = 2 second
bool loginSuccess = false;
        SDL_Color white = { 255, 255, 255, 255 };
    SDL_Color grey = { 100, 100, 100, 255 };
    SDL_Color black = { 0, 0, 0, 255 };
    SDL_Color darkgreen = { 0, 50, 0, 255  }; 
    SDL_Color maroon = { 128, 0, 0, 255 };
 
    std::string username, password;
    
   bool enteringUsername;
bool enteringpassword;
   

bool isPasswordVisible = false;
bool isCheckboxChecked = false;


   int boxPadding = 20;
    int checkboxSize=10;

   
    SDL_Rect outerBox ;


    // Declare variables for text dimensions
    int textWidth1, textHeight1;
    int textWidth2, textHeight2;
    int textWidth3, textHeight3;
    int textWidth4, textHeight4;
    int textWidth5, textHeight5;
    int textWidth6, textHeight6;
    int textWidth7, textHeight7;
    int textWidth8, textHeight8;
 int passwordBoxWidth = 250;
     int usernameBoxWidth = 250;
int loginButtonWidth = 100;
 int signUpBoxWidth = 400;
int boxWidth = Width- 6* boxPadding;

int inputBoxHeight = 30;//(becaasue its same for both username and password boxes)   
    int loginButtonHeight = 30;
    int signUpBoxHeight = 35;
    int boxHeight = Height - 10* boxPadding;

    
    // Declare variables for dynamic text positions
    int textY1, textY2, textY3, textY4, textY5, textY6, textY7,textY8;
int usernameBoxY;
int passwordBoxY ;
int loginButtonY ;
int signUpBoxY;
    int boxY ;
   int  checkboxY;
 int tickStartY;
 int tickMiddleY;
int tickEndY;


    int textX1, textX2, textX3, textX4, textX5, textX6, textX7,textX8;
    int usernameBoxX ; 
int passwordBoxX;
int loginButtonX ;
int signUpBoxX;
int boxX ;
 int  checkboxX;
int tickStartX ;
int tickMiddleX ;
int tickEndX;
    
    


public:
    LoginScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* digitalFont):State(window ,renderer, digitalFont )
        ,username(""), password(""), enteringUsername(true),enteringpassword(false)
        
        
         {
            SDL_StartTextInput();
        // Initialization 

    }
    
 


void handleEvents(SDL_Event& event) override {
    if (event.type == SDL_TEXTINPUT) {
        if (enteringUsername) {
            username += event.text.text;
        } else if (enteringpassword) {
            password += event.text.text;
        } 
    } else if (event.type == SDL_KEYDOWN) {
        switch (event.key.keysym.sym) {
            case SDLK_BACKSPACE:
                 if (enteringUsername && !username.empty()) {
                   username.pop_back();
                } else if (enteringpassword && !password.empty()) {
                    password.pop_back();
                }
                break;

case SDLK_RETURN:
     if (enteringUsername && !username.empty()) {
        enteringUsername = false;
        enteringpassword = true;
    } else if (enteringpassword && !username.empty() && !password.empty()) {
                        if (validateLogin(username, password)) {
                            loginMessage = "Login successful!";
                            loginMessageColor = darkgreen;
                            loginMessageTime = SDL_GetTicks();
                            loginSuccess = true;
                        } else {
                            loginMessage = "Login failed. Invalid username or password.";
                            loginMessageColor = maroon;
                             loginMessageTime = SDL_GetTicks();
                        loginSuccess = false; // Login failed
                        }
                    }
                break;
            default:
                break;







                
        }
    } else if (event.type == SDL_MOUSEBUTTONDOWN || event.type == SDL_FINGERDOWN) {
        int mouseX, mouseY;

        if (event.type == SDL_MOUSEBUTTONDOWN) {
            mouseX = event.button.x;
            mouseY = event.button.y;
        } else { // SDL_FINGERDOWN
            mouseX = event.tfinger.x * Width;
            mouseY = event.tfinger.y * Height;
        }

        std::cout << "Click at (" << mouseX << ", " << mouseY << ")" << std::endl;

        if (mouseX >= usernameBoxX && mouseX <= usernameBoxX + usernameBoxWidth && mouseY >= usernameBoxY && mouseY <= usernameBoxY +  inputBoxHeight) {
            
            enteringUsername = true;
            enteringpassword = false;
           false;
        } else if (mouseX >= passwordBoxX && mouseX <= passwordBoxX + passwordBoxWidth && mouseY >= passwordBoxY && mouseY <= passwordBoxY + inputBoxHeight) {
            
            enteringUsername = false;
            enteringpassword = true;
           
        } 
        
        
         else if (mouseX >= textX5 && mouseX <= textX5 + textWidth5 && mouseY >= textY5 && mouseY <= textY5 + textHeight5) {
            std::cout << "Login button clicked" << std::endl;
    if (validateLogin(username, password)) {
                            loginMessage = "Login successful!";
                            loginMessageColor = darkgreen;
                            loginMessageTime = SDL_GetTicks();
                            loginSuccess = true;
                        } else {
                            loginMessage = "Login failed. Invalid username or password.";
                            loginMessageColor = maroon;
                             loginMessageTime = SDL_GetTicks();
                        loginSuccess = false; // Login failed
                        }

                        


        } else if (mouseX >= textX6 && mouseX <= textX6 + textWidth6 && mouseY >= textY6 && mouseY <= textY6 + textHeight6) {
            std::cout << "Forgot password link clicked" << std::endl;
            changeState ( S_VERIFICATION_SCREEN); // Switch to the Verification screen
        } else if (mouseX >= textX7 && mouseX <= textX7 + textWidth7 && mouseY >= textY7 && mouseY <= textY7 + textHeight7) {
            std::cout << "Sign-up link clicked" << std::endl;
            changeState (SIGNUP_SCREEN); // Switch to the sign-up screen
        }
 if (mouseX >= passwordBoxX && mouseX <= passwordBoxX + passwordBoxWidth &&
                    mouseY >= passwordBoxY && mouseY <= passwordBoxY + inputBoxHeight) {
                    // Toggle the password visibility flag
                    isPasswordVisible = !isPasswordVisible;
                }

                // Check if the click is inside the checkbox
                else if (mouseX >= checkboxX && mouseX <= checkboxX + checkboxSize &&
                    mouseY >= checkboxY && mouseY <= checkboxY + checkboxSize) {
                    // Toggle the checkbox state
                    isCheckboxChecked = !isCheckboxChecked;
                    // Update the password visibility based on the checkbox state
                    isPasswordVisible = isCheckboxChecked;
                }
    }
}













 ///////////////
            
        //      else if (event.type == SDL_TEXTINPUT) {
        //     if (enteringUsername && username.size() < 15) {
        //         username += event.text.text;
        //     } else if (!enteringUsername && password.size() < 15) {
        //         password += event.text.text;
        //     }
        // }




      

    
    void update() override {
        // Update logic for Login Screen
    }

    void render() override {
// Calculate dynamic positions based on window size
  textY1 = boxY -30; 
    textY2 = boxY + (Height / 12) + 1;
    textY3 = boxY + (Height / 12) + 50;
    textY4 = boxY + (Height / 12) + 95;
    textY5 = boxY + (Height / 12) + 160;
    textY6 = boxY + (Height / 12) + 200;
    textY7 = boxY + (Height / 12) + 250;
    textY8 =  textY4 + 30;

    usernameBoxY = textY3;
    passwordBoxY = usernameBoxY + inputBoxHeight + 10;
loginButtonY = textY5;
signUpBoxY = (textY7)-7;


  boxY = (Height - boxHeight) / 2;
checkboxY = textY4 + 38;
 tickStartY = checkboxY + checkboxSize / 2;
     tickMiddleY = checkboxY + checkboxSize - checkboxSize / 4;
     tickEndY = checkboxY + checkboxSize / 4;


const char* text1 = "Login to Continue";
const char* text2 = "NEURABYTE";
std::string text3 = "User ID " + username;
 std::string text4 = "Password " + (isPasswordVisible ? password : std::string(password.size(), '*'));
// std::string text4 = "Password " + password;

const char* text5 = "Login"; // Login button
const char* text6 = "Forgot Password?"; // Forgot password link
const char* text7 = "Don't have an account? Sign up"; // Sign-up link
const char* text8 = "Show Password"; // Show password label


// Get the dimensions of the text
TTF_SizeText(digitalFont, text1, &textWidth1, &textHeight1);
TTF_SizeText(digitalFont, text2, &textWidth2, &textHeight2);
TTF_SizeText(digitalFont, text3.c_str(), &textWidth3, &textHeight3);
TTF_SizeText(digitalFont, text4.c_str(), &textWidth4, &textHeight4);
TTF_SizeText(digitalFont, text5, &textWidth5, &textHeight5);
TTF_SizeText(digitalFont, text6, &textWidth6, &textHeight6);
TTF_SizeText(digitalFont, text7, &textWidth7, &textHeight7);
 TTF_SizeText(digitalFont, text8, &textWidth8, &textHeight8);



// Calculate x positions to center the text within the box
     textX1 = (Width - textWidth1) / 2;
    textX2 = boxX + (boxWidth - textWidth2) / 2;
    textX3 = boxX + (boxWidth - textWidth3) / 2;
    textX4 = boxX + (boxWidth - textWidth4) / 2;
    textX5 = boxX + (boxWidth - textWidth5) / 2;
    textX6 = boxX + (boxWidth - textWidth6) / 2;
    textX7 = boxX + (boxWidth - textWidth7) / 2;
    textX8 = passwordBoxX+20;

    usernameBoxX = boxX + (boxWidth - usernameBoxWidth) / 2;
    passwordBoxX = boxX + (boxWidth - passwordBoxWidth) / 2;

  loginButtonX = boxX +(boxWidth - loginButtonWidth) / 2;
  
signUpBoxX=boxX +(boxWidth - signUpBoxWidth) / 2;
 boxX = (Width - boxWidth) / 2;
     checkboxX = passwordBoxX+20;
  tickStartX = checkboxX + checkboxSize / 4;
tickMiddleX = checkboxX + checkboxSize / 2;
 tickEndX = checkboxX + checkboxSize - checkboxSize / 4;




    



SDL_Rect outerBox = { boxX, boxY, boxWidth, boxHeight };
 // Set the color for the fill (black) and render the inside of the box
    SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
    SDL_RenderFillRect(renderer, &outerBox);

  
renderRoundedRect(renderer,usernameBoxX, usernameBoxY, usernameBoxWidth, inputBoxHeight, radius, white);

renderRoundedRect(renderer,  passwordBoxX, passwordBoxY,  passwordBoxWidth, inputBoxHeight, radius, white);

renderRoundedRect(renderer,  loginButtonX, loginButtonY, loginButtonWidth, loginButtonHeight, radius,darkgreen);

renderRoundedRect(renderer,signUpBoxX, signUpBoxY, signUpBoxWidth, signUpBoxHeight, radius,maroon );



    SDL_Rect checkbox = { checkboxX, checkboxY, checkboxSize, checkboxSize };
    SDL_SetRenderDrawColor(renderer, 255, 255, 255, 255);
    SDL_RenderFillRect(renderer, &checkbox);

 // Render checkmark if checkbox is checked
if (isCheckboxChecked) {
    SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);

    // Draw the tick mark lines
    SDL_RenderDrawLine(renderer, tickStartX, tickStartY, tickMiddleX, tickMiddleY);
    SDL_RenderDrawLine(renderer, tickMiddleX, tickMiddleY, tickEndX, tickEndY);
}



// Render text inside boxes
    renderText(text1, textX1, textY1, white, digitalFont, renderer); // Login to Continue
    renderText(text2, textX2, textY2, white, digitalFont, renderer); // NEURABYTE



 renderText(text5, textX5, textY5, white, digitalFont, renderer); // Login button
    renderText(text6, textX6, textY6, white, digitalFont, renderer); // Forgot password link
    renderText(text7, textX7, textY7, white, digitalFont, renderer); // Sign-up link
renderText(text8, textX8 + checkboxSize + 10, textY8, white, digitalFont, renderer);


    
    //render user id and password
    
   // Render user ID
    if (enteringUsername && !username.empty()) {
        renderText(username.c_str(), usernameBoxX, usernameBoxY, black, digitalFont, renderer);
    } else {

 if (username.empty()) {
         renderText("User ID ", textX3, textY3, grey, digitalFont, renderer);
    } else {
        renderText(username.c_str(), usernameBoxX, usernameBoxY, black, digitalFont, renderer);
    }
}
    

   // Render password
if (enteringpassword && !password.empty()) {
    renderText((isPasswordVisible ? password : std::string(password.size(), '*')).c_str(), passwordBoxX, passwordBoxY, black, digitalFont, renderer);
} else {
    if (password.empty()) {
        renderText("Password ", textX4, textY4, grey, digitalFont, renderer);
    } else {
        renderText((isPasswordVisible ? password : std::string(password.size(), '*')).c_str(), passwordBoxX, passwordBoxY, black, digitalFont, renderer);
    }
}

 if (!loginMessage.empty()) {
        int loginMessageWidth, loginMessageHeight;
        TTF_SizeText(digitalFont, loginMessage.c_str(), &loginMessageWidth, &loginMessageHeight);
        int loginMessageX = (Width - loginMessageWidth) / 2;
        int loginMessageY = textY2 + textHeight2; 

        renderText(loginMessage.c_str(), loginMessageX, loginMessageY, loginMessageColor, digitalFont, renderer);

        // Check if enough time has passed since showing the message
        Uint32 currentTime = SDL_GetTicks();
        if (currentTime - loginMessageTime >= LOGIN_MESSAGE_DISPLAY_TIME && loginSuccess) {
            // Time elapsed and login was successful, change state to Main Dashboard Screen
            changeState(MAIN_DASHBOARD);
        }
 }






    
    SDL_RenderPresent(renderer);
}


    void cleanup() override {
        // Implement cleanup logic 
    }
    

};


// SignupScreenState class
class SignupScreenState : public State {
    private:
    std::string emailAddress,username,password,reconfirmedPassword;


bool enteringemailAddress;
bool enteringUsername;
bool enteringpassword;
bool enteringreconfirmedPassword;



   int emailboxWidth=250;
     int usernameboxWidth=250;
   int  PasswordboxWidth=250;
     int reconfirmpasswordboxWidth=250;
     int signupbuttonWidth=100;
     int loginbuttonWidth=400;

 int emailboxHeight=25 ;
     int usernameboxHeight=25 ; 
   int  PasswordboxHeight=25 ;
     int reconfirmpasswordboxHeight=25 ;
     int signupbuttonHeight=30 ;
     int loginbuttonHeight =30;

 int emailboxX ;
     int usernameboxX ;
   int  PasswordboxX ;
     int reconfirmpasswordboxX ;
     int signupbuttonX ;
     int loginbuttonX ;
int boxX ;

 int emailboxY;
     int usernameboxY; 
   int  PasswordboxY;
     int reconfirmpasswordboxY;
     int signupbuttonY;
     int loginbuttonY;
    int boxY ;

int boxPadding = 20;
int boxWidth = Width- 6* boxPadding;
    int boxHeight = Height - 10* boxPadding;
 SDL_Rect  emailboxRect;
      SDL_Rect usernameboxRect; 
    SDL_Rect  PasswordboxRect;
    SDL_Rect  reconfirmpasswordboxRect;
SDL_Rect outerBox ;



// Declare variables for text dimensions
    int textWidth1, textHeight1;
    int textWidth2, textHeight2;
    int textWidth3, textHeight3;
    int textWidth4, textHeight4;
    int textWidth5, textHeight5;
    int textWidth6, textHeight6;
    int textWidth7, textHeight7;
    int textWidth8a, textHeight8a;
    int textWidth8b, textHeight8b;

    int textWidth9, textHeight9;
    
    // Declare variables for dynamic text positions
    int textY1, textY2, textY3, textY4, textY5, textY6, textY7,textY8a,textY8b, textY9;

    int textX1, textX2, textX3, textX4, textX5, textX6, textX7, textX8a, textX8b, textX9;

 




public:
    SignupScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* digitalFont):State(window ,renderer, digitalFont ),emailAddress(""), username(""), password(""), reconfirmedPassword(""),
      enteringemailAddress(true), enteringUsername(false), enteringpassword(false), enteringreconfirmedPassword(false)
         {
            
SDL_StartTextInput();

        // more Initialization if needed
    }
  


void handleEvents(SDL_Event& event) override {
    if (event.type == SDL_TEXTINPUT) {
        if (enteringemailAddress) {
            emailAddress += event.text.text;
        } else if (enteringUsername) {
            username += event.text.text;
        } else if (enteringpassword) {
            password += event.text.text;
        } else if (enteringreconfirmedPassword) {
            reconfirmedPassword += event.text.text;
        }
    } else if (event.type == SDL_KEYDOWN) {
        switch (event.key.keysym.sym) {
            case SDLK_BACKSPACE:
                if (enteringemailAddress && !emailAddress.empty()) {
                    emailAddress.pop_back();
                } else if (enteringUsername && !username.empty()) {
                    username.pop_back();
                } else if (enteringpassword && !password.empty()) {
                    password.pop_back();
                } else if (enteringreconfirmedPassword && !reconfirmedPassword.empty()) {
                    reconfirmedPassword.pop_back();
                }
                break;

case SDLK_RETURN:
    if (enteringemailAddress && !emailAddress.empty()) {
        enteringemailAddress = false;
        enteringUsername = true;
    } else if (enteringUsername && !username.empty()) {
        enteringUsername = false;
        enteringpassword = true;
    } else if (enteringpassword && !password.empty()) {
        enteringpassword = false;
        enteringreconfirmedPassword = true;
    } else if (enteringreconfirmedPassword && !reconfirmedPassword.empty()) {
        enteringreconfirmedPassword = false;
        saveUserDataToDatabase(); 


        changeState(F_VERIFICATION_SCREEN);
    }
    break;
            default:
                break;
        }
    } else if (event.type == SDL_MOUSEBUTTONDOWN || event.type == SDL_FINGERDOWN) {
        int mouseX, mouseY;

        if (event.type == SDL_MOUSEBUTTONDOWN) {
            mouseX = event.button.x;
            mouseY = event.button.y;
        } else { // SDL_FINGERDOWN
            mouseX = event.tfinger.x * Width;
            mouseY = event.tfinger.y * Height;
        }

        std::cout << "Click at (" << mouseX << ", " << mouseY << ")" << std::endl;

        if (mouseX >= emailboxX && mouseX <= emailboxX + emailboxWidth && mouseY >= emailboxY && mouseY <= emailboxY + emailboxHeight) {
            enteringemailAddress = true;
            enteringUsername = false;
            enteringpassword = false;
            enteringreconfirmedPassword = false;
        } else if (mouseX >= usernameboxX && mouseX <= usernameboxX + usernameboxWidth && mouseY >= usernameboxY && mouseY <= usernameboxY + usernameboxHeight) {
            enteringemailAddress = false;
            enteringUsername = true;
            enteringpassword = false;
            enteringreconfirmedPassword = false;
        } else if (mouseX >= PasswordboxX && mouseX <= PasswordboxX + PasswordboxWidth && mouseY >= PasswordboxY && mouseY <= PasswordboxY + PasswordboxHeight) {
            enteringemailAddress = false;
            enteringUsername = false;
            enteringpassword = true;
            enteringreconfirmedPassword = false;
        } else if (mouseX >= reconfirmpasswordboxX && mouseX <= reconfirmpasswordboxX + reconfirmpasswordboxWidth && mouseY >= reconfirmpasswordboxY && mouseY <= reconfirmpasswordboxY + reconfirmpasswordboxHeight) {
            enteringemailAddress = false;
            enteringUsername = false;
            enteringpassword = false;
            enteringreconfirmedPassword = true;
        } 
        
        else if (mouseX >= textX9 && mouseX <= textX9 + textWidth9 && mouseY >= textY9 && mouseY <= textY9 + textHeight9) {
            std::cout << "Login button clicked" << std::endl;
            changeState(LOGIN_SCREEN);
        } else if (mouseX >= textX7 && mouseX <= textX7 + textWidth7 && mouseY >= textY7 && mouseY <= textY7 + textHeight7) {
            std::cout << "Sign up button clicked" << std::endl;
              saveUserDataToDatabase(); 
            changeState(F_VERIFICATION_SCREEN);
        }
    }
}


    
    void update() override {
        // Update logic for Signup Screen
    }
    
    void render() override {

SDL_Color white = { 255, 255, 255, 255 };
    SDL_Color grey = { 100, 100, 100, 255 };
    SDL_Color black = { 0, 0, 0, 255 };
    SDL_Color darkgreen = { 0, 50, 0, 255  }; 
    SDL_Color maroon = { 128, 0, 0, 255 };
 
// Calculate dynamic positions based on window size
  textY1 = boxY -30; 
    textY2 = boxY + (Height / 30) ;


    textY3 = boxY + (Height / 30) + 60;
    textY4 = boxY + (Height / 30) + 90;
    textY5 = boxY + (Height / 30) + 120;
    textY6 = boxY + (Height / 30) + 150;


    textY7 = boxY + (Height / 30) + 190;
    textY8a = boxY + (Height /30) + 240;
    textY8b = boxY + (Height /30) + 260;
    textY9 = boxY + (Height / 30) + 300;

 emailboxY = textY3    ;
      usernameboxY=  textY4 ;
     PasswordboxY= textY5  ;
      reconfirmpasswordboxY= textY6 ;
      signupbuttonY=textY7  ;
      loginbuttonY= textY9 ;



boxY = (Height - boxHeight) / 2;

   
       const char* text1 = "Sign up to upload Data";
const char* text2 = "NeuraByte";
std::string text3 = "Email Address " + emailAddress;
std::string text4 = "User ID " + username;
std::string text5 = "Password " + password;
std::string text6 = "Reconfirm Password " + reconfirmedPassword;
const char* text7 = "Sign up"; // Sign-up button
const char* text8a = "By signing up, you agree to our Terms,";
    const char* text8b = "Data Policy, and Cookies Policy";
const char* text9 = "Already have an account? Log in"; // Login link


// Get the dimensions of the text
TTF_SizeText(digitalFont, text1, &textWidth1, &textHeight1);
TTF_SizeText(digitalFont, text2, &textWidth2, &textHeight2);
TTF_SizeText(digitalFont, text3.c_str(), &textWidth3, &textHeight3);
TTF_SizeText(digitalFont, text4.c_str(), &textWidth4, &textHeight4);


TTF_SizeText(digitalFont, text5.c_str(), &textWidth5, &textHeight5);
TTF_SizeText(digitalFont, text6.c_str(), &textWidth6, &textHeight6);
TTF_SizeText(digitalFont, text7, &textWidth7, &textHeight7);
 TTF_SizeText(digitalFont, text8a, &textWidth8a, &textHeight8a);
 TTF_SizeText(digitalFont, text8b, &textWidth8b, &textHeight8b);
 TTF_SizeText(digitalFont, text9, &textWidth9, &textHeight9);



// Calculate x positions to center the text within the box
     textX1 = (Width - textWidth1) / 2;
    textX2 = boxX + (boxWidth - textWidth2) / 2;
    textX3 = boxX + (boxWidth - textWidth3) / 2;
    textX4 = boxX + (boxWidth - textWidth4) / 2;
    textX5 = boxX + (boxWidth - textWidth5) / 2;
    textX6 = boxX + (boxWidth - textWidth6) / 2;
    textX7 = boxX + (boxWidth - textWidth7) / 2;
    textX8a = boxX + (boxWidth - textWidth8a) / 2;
    textX8b = boxX + (boxWidth - textWidth8b) / 2;
    textX9 = boxX + (boxWidth - textWidth9) / 2;


emailboxX =  boxX + (boxWidth - emailboxWidth) / 2  ;
      usernameboxX=  boxX + (boxWidth -  usernameboxWidth) / 2  ;
     PasswordboxX=   boxX + (boxWidth - PasswordboxWidth) / 2  ;
      reconfirmpasswordboxX=   boxX + (boxWidth - emailboxWidth) / 2  ;


      signupbuttonX=  boxX + (boxWidth - signupbuttonWidth) / 2  ;
      
      loginbuttonX=   boxX + (boxWidth - loginbuttonWidth) / 2  ;
boxX = (Width - boxWidth) / 2;



SDL_Rect outerBox = { boxX, boxY, boxWidth, boxHeight };
SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
    SDL_RenderFillRect(renderer, &outerBox);

/*

          renderRoundedRect(renderer, emailboxX, emailboxY, emailboxWidth, emailboxHeight, radius, white);

          
          renderRoundedRect(renderer, usernameboxX, usernameboxY, usernameboxWidth, usernameboxHeight, radius, white);

          
          renderRoundedRect(renderer, PasswordboxX, PasswordboxY, PasswordboxWidth, PasswordboxHeight, radius, white);

          
          renderRoundedRect(renderer,reconfirmpasswordboxX, reconfirmpasswordboxY, reconfirmpasswordboxWidth, reconfirmpasswordboxHeight, radius, white);
*/


   // Define positions and dimensions of input boxes
    SDL_Rect emailbox = { emailboxX, emailboxY, emailboxWidth, emailboxHeight };


// Set the color for the fill (white)
    SDL_SetRenderDrawColor(renderer, 255, 255, 255, 255);

    // Render the username input box filled with white color
    SDL_RenderFillRect(renderer, &emailbox);
//text3
    SDL_Rect usernamebox = { usernameboxX, usernameboxY, usernameboxWidth, usernameboxHeight };


// Set the color for the fill (white)
    SDL_SetRenderDrawColor(renderer, 255, 255, 255, 255);

    // Render the username input box filled with white color
    SDL_RenderFillRect(renderer, &usernamebox);

    //text4
    SDL_Rect Passwordbox = { PasswordboxX, PasswordboxY, PasswordboxWidth, PasswordboxHeight };
// Set the color for the fill (white)
    SDL_SetRenderDrawColor(renderer, 255, 255, 255, 255);
    // Render the username input box filled with white color
    SDL_RenderFillRect(renderer, &Passwordbox);
//text5

    SDL_Rect reconfirmpasswordbox = { reconfirmpasswordboxX, reconfirmpasswordboxY, reconfirmpasswordboxWidth, reconfirmpasswordboxHeight };



    // Set the color for the fill (white)
    SDL_SetRenderDrawColor(renderer, 255, 255, 255, 255);

    // Render the username input box filled with white color
    SDL_RenderFillRect(renderer, &reconfirmpasswordbox);


          renderRoundedRect(renderer, signupbuttonX, signupbuttonY, signupbuttonWidth, signupbuttonHeight, radius,darkgreen);

          
          renderRoundedRect(renderer, loginbuttonX, loginbuttonY, loginbuttonWidth, loginbuttonHeight, radius, darkgreen);


        renderText(text1, textX1, textY1, white, digitalFont, renderer);
        renderText(text2, textX2, textY2, white, digitalFont, renderer);
        renderText(text7, textX7, textY7, white, digitalFont, renderer);
        renderText(text8a, textX8a, textY8a, grey,digitalFont, renderer);
        renderText(text8b, textX8b, textY8b, grey, digitalFont, renderer);
        renderText(text9, textX9, textY9, white, digitalFont, renderer);
       

  
// Render email address
if (enteringemailAddress && !emailAddress.empty()) {
    renderText(emailAddress.c_str(), emailboxX, emailboxY, black, digitalFont, renderer);
} else {
    // Render placeholder text only if emailAddress is empty
    if (emailAddress.empty()) {
        renderText("Email Address ", textX3, textY3, grey, digitalFont, renderer);
    } else {
        renderText(emailAddress.c_str(), emailboxX, emailboxY, black, digitalFont, renderer);
    }
}


  


    // Render user ID
    if (enteringUsername && !username.empty()) {
        renderText(username.c_str(), usernameboxX, usernameboxY, black, digitalFont, renderer);
    } else {

 if (username.empty()) {
         renderText("User ID ", textX4, textY4, grey, digitalFont, renderer);
    } else {
        renderText(username.c_str(), usernameboxX, usernameboxY, black, digitalFont, renderer);
    }
}
    

    // Render password
    if (enteringpassword && !password.empty()) {
        renderText(password.c_str(), PasswordboxX, PasswordboxY, black, digitalFont, renderer);
    } else {
         if (password.empty()) {
            
        renderText("Password ", textX5, textY5, grey, digitalFont, renderer);
    } else {
       renderText(password.c_str(), PasswordboxX, PasswordboxY, black, digitalFont, renderer);
    }
}
   

    // Render reconfirm password
    if (enteringreconfirmedPassword && !reconfirmedPassword.empty()) {
        renderText(reconfirmedPassword.c_str(), reconfirmpasswordboxX, reconfirmpasswordboxY, black, digitalFont, renderer);
    } else {

         if (reconfirmedPassword.empty()) {
           
        renderText("Reconfirm Password ", textX6, textY6, grey, digitalFont, renderer);
        }else {
         renderText(reconfirmedPassword.c_str(), reconfirmpasswordboxX, reconfirmpasswordboxY, black, digitalFont, renderer);
    }
}
    

   

    }

    
    void cleanup() override {
        // Implement cleanup logic 
    }

// Method to save user data to database
  void saveUserDataToDatabase() {
    // Validate input
    if (emailAddress.empty() || username.empty() || password.empty() || reconfirmedPassword.empty()) {
        std::cerr << "Error: All fields are required." << std::endl;
        return;
    }
    
    // Check if passwords match
    if (password != reconfirmedPassword) {
        std::cerr << "Error: Passwords do not match." << std::endl;
        return;
    }

    // Hash the password
    std::string hashedPassword = hashPassword(password);

    // Create User object
    User newUser(emailAddress, username, hashedPassword);

    // Save to database
    if (insertUser(newUser)) {
        std::cout << "User registered successfully." << std::endl;
    } else {
        std::cerr << "Error: Failed to register user." << std::endl;
    }
}

};


class NavigationMenu : public State {
protected:
    SDL_Color white = { 255, 255, 255, 255 };
    SDL_Color grey = { 100, 100, 100, 255 };
    SDL_Color black = { 0, 0, 0, 255 };
    SDL_Color darkgreen = { 0, 50, 0, 255 };
    SDL_Color maroon = { 128, 0, 0, 255 };


        int HomeiconWidth= 40;
        int ProfileiconWidth= 40;
        int SettingsiconWidth= 40;
        int CognitiveStatsiconWidth= 40;
        int DataStatsiconWidth= 40;
        int TargetsiconWidth= 40;
        int SystemHealthiconWidth= 40;

        
        int textWidthHome ,textWidthProfile ,textWidthSettings ,textWidthCognitiveStat ,textWidthDataStats ,textWidthTargets,textWidthSystemHealth;

         int textHeightHome ,textHeightProfile ,textHeightSettings ,textHeightCognitiveStat ,textHeightDataStats ,textHeightTargets,textHeightSystemHealth;


  int textYHome ,textYProfile ,textYSettings ,textYCognitiveStat ,textYDataStats ,textYTargets,textYSystemHealth;
int SearchboxHeight=30;

         int HomeiconHeight= 40;
        int ProfileiconHeight= 40;
        int SettingsiconHeight= 40;
        int CognitiveStatsiconHeight= 40;
        int DataStatsiconHeight= 40;
        int TargetsiconHeight= 40;
        int SystemHealthiconHeight= 40;

         int HomeiconX, ProfileiconX, SettingsiconX, CognitiveStatsiconX, DataStatsiconX, TargetsiconX,SystemHealthiconX;

         float HomeiconY, ProfileiconY, SettingsiconY, CognitiveStatsiconY, DataStatsiconY, TargetsiconY, SystemHealthiconY;


// Define the proportional gap based on the window height
float proportionalGap = Height / 10.0;


       
      
        SDL_Rect  Searchicon;
        SDL_Rect  Homeicon;
         SDL_Rect  Profileicon;
         SDL_Rect  Settingsicon;
         SDL_Rect  CognitiveStatsicon;
         SDL_Rect  DataStatsicon;
         SDL_Rect  Targetsicon;
         SDL_Rect  SystemHealthicon;









public:
    NavigationMenu(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* digitalFont)
        : State(window, renderer, digitalFont) {
        SDL_StartTextInput();
        // Initialize other necessary variables if needed
    }

    virtual void handleEvents(SDL_Event& event) override {
        if (event.type == SDL_MOUSEBUTTONDOWN || event.type == SDL_FINGERDOWN) {
        int mouseX, mouseY;

        if (event.type == SDL_MOUSEBUTTONDOWN) {
            mouseX = event.button.x;
            mouseY = event.button.y;
        } else { // SDL_FINGERDOWN
            mouseX = event.tfinger.x * Width;
            mouseY = event.tfinger.y * Height;
        }

        std::cout << "Click at (" << mouseX << ", " << mouseY << ")" << std::endl;
  if (mouseX >= HomeiconX && mouseX <= HomeiconX + HomeiconWidth && mouseY >=HomeiconY && mouseY <= HomeiconY + HomeiconHeight) {
            std::cout << "Home Icon  clicked" << std::endl;
            changeState(MAIN_DASHBOARD);

}
else if (mouseX >= ProfileiconX && mouseX <= ProfileiconX + ProfileiconWidth && mouseY >= ProfileiconY && mouseY <= ProfileiconY +  ProfileiconHeight) {
            std::cout << "PROFILE_ Icon  clicked" << std::endl;
            changeState(PROFILE_SCREEN);

}

else if (mouseX >=SettingsiconX && mouseX <= SettingsiconX + SettingsiconWidth && mouseY >= SettingsiconY && mouseY <= SettingsiconY + SettingsiconHeight) {
            std::cout << " SETTINGS gear Icon  clicked" << std::endl;
            changeState( SETTINGS_SCREEN);

}

else if (mouseX >= CognitiveStatsiconX && mouseX <= CognitiveStatsiconX + CognitiveStatsiconWidth && mouseY >= CognitiveStatsiconY && mouseY <= CognitiveStatsiconY + CognitiveStatsiconHeight) {
    std::cout << "COGNITIVE_STATS Icon clicked" << std::endl;
    changeState(COGNITIVE_STATS_SCREEN);
}
else if (mouseX >= DataStatsiconX && mouseX <= DataStatsiconX + DataStatsiconWidth && mouseY >= DataStatsiconY && mouseY <= DataStatsiconY + DataStatsiconHeight) {
    std::cout << "DATA_STATS Icon clicked" << std::endl;
    changeState(DATA_STATS_SCREEN);
}
else if (mouseX >= TargetsiconX && mouseX <= TargetsiconX + TargetsiconWidth && mouseY >= TargetsiconY && mouseY <= TargetsiconY + TargetsiconHeight) {
    std::cout << "TARGETS Icon clicked" << std::endl;
    changeState(TARGETS_SCREEN);
}
else if (mouseX >= SystemHealthiconX && mouseX <= SystemHealthiconX + SystemHealthiconWidth && mouseY >= SystemHealthiconY && mouseY <= SystemHealthiconY + SystemHealthiconHeight) {
    std::cout << "SYSTEM_HEALTH Icon clicked" << std::endl;
    changeState(SYSTEM_HEALTH_SCREEN);
}

}
    }

   virtual  void update() override {
        // Update logic for System Health Screen if needed
    }

  virtual   void render() override {
       
         HomeiconY =  (((Height - SearchboxHeight) / 2)-250)+ (Height / 10);
         ProfileiconY = HomeiconY + proportionalGap;
         SettingsiconY = ProfileiconY + proportionalGap;
         CognitiveStatsiconY = SettingsiconY + proportionalGap;
         DataStatsiconY = CognitiveStatsiconY + proportionalGap;
         TargetsiconY = DataStatsiconY + proportionalGap;
         SystemHealthiconY = TargetsiconY + proportionalGap;

const char *textHome = "Home";
const char *textProfile = "Profile";
const char *textSettings = "Settings";
const char *textCognitiveStats = "Cognitive";
const char *textDataStats = "Data";
const char *textTargets = "Targets";
const char *textSystemHealth = "System";

TTF_SizeText(digitalFont, textHome, &textWidthHome, &textHeightHome);
TTF_SizeText(digitalFont, textProfile, &textWidthProfile, &textHeightProfile);
TTF_SizeText(digitalFont, textSettings, &textWidthSettings, &textHeightSettings);
TTF_SizeText(digitalFont, textCognitiveStats, &textWidthCognitiveStat, &textHeightCognitiveStat);
TTF_SizeText(digitalFont, textDataStats, &textWidthDataStats, &textHeightDataStats);
TTF_SizeText(digitalFont, textTargets, &textWidthTargets, &textHeightTargets);
TTF_SizeText(digitalFont, textSystemHealth, &textWidthSystemHealth, &textHeightSystemHealth);


         HomeiconX = 0;
         ProfileiconX = 0;
         SettingsiconX = 0;
         CognitiveStatsiconX = 0;
         DataStatsiconX = 0;
         TargetsiconX = 0;
         SystemHealthiconX = 0;

SDL_Texture* homeIconTexture = loadTexture("C:/NEW/assets/HOME.jpg", renderer);
SDL_Texture* profileIconTexture = loadTexture("C:/NEW/assets/USERPROFILE.jpg", renderer);
SDL_Texture* settingsIconTexture = loadTexture("C:/NEW/assets/SETTINGS.jpg", renderer);
SDL_Texture* cognitiveStatsIconTexture = loadTexture("C:/NEW/assets/BRAIN.jpg", renderer);
SDL_Texture* dataStatsIconTexture = loadTexture("C:/NEW/assets/FILES.jpg", renderer);
SDL_Texture* targetsIconTexture = loadTexture("C:/NEW/assets/targets.jpg", renderer);
SDL_Texture* systemHealthIconTexture = loadTexture("C:/NEW/assets/SYSTEMHEALTHCARE.png", renderer);



// Now create and render the icons with these calculated Y positions
 SDL_Rect Homeicon = {HomeiconX, (int)HomeiconY, HomeiconWidth, HomeiconHeight};
 SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
 SDL_RenderCopy(renderer, homeIconTexture, NULL, &Homeicon);

 SDL_Rect Profileicon = {ProfileiconX, (int)ProfileiconY, ProfileiconWidth, ProfileiconHeight};
SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
 SDL_RenderCopy(renderer, profileIconTexture, NULL, &Profileicon);

 SDL_Rect Settingsicon = {SettingsiconX, (int)SettingsiconY, SettingsiconWidth, SettingsiconHeight};
 SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
 SDL_RenderCopy(renderer, settingsIconTexture, NULL, &Settingsicon);

 SDL_Rect CognitiveStatsicon = {CognitiveStatsiconX, (int)CognitiveStatsiconY, CognitiveStatsiconWidth, CognitiveStatsiconHeight};
 SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
 SDL_RenderCopy(renderer, cognitiveStatsIconTexture, NULL, &CognitiveStatsicon);

 SDL_Rect DataStatsicon = {DataStatsiconX, (int)DataStatsiconY, DataStatsiconWidth, DataStatsiconHeight};
 SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
 SDL_RenderCopy(renderer, dataStatsIconTexture, NULL, &DataStatsicon);

 SDL_Rect Targetsicon = {TargetsiconX, (int)TargetsiconY, TargetsiconWidth, TargetsiconHeight};
 SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
 SDL_RenderCopy(renderer, targetsIconTexture, NULL, &Targetsicon);

 SDL_Rect SystemHealthicon = {SystemHealthiconX, (int)SystemHealthiconY, SystemHealthiconWidth, SystemHealthiconHeight};
 SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
 SDL_RenderCopy(renderer, systemHealthIconTexture, NULL, &SystemHealthicon);


// Load the smaller font for icon labels
TTF_Font* smallFont = TTF_OpenFont("C:/NEW/assets/Nunito-Regular.ttf", 12);

// Render the icon labels
renderText(textHome, HomeiconX, HomeiconY +HomeiconHeight, white, smallFont, renderer);
renderText(textProfile, ProfileiconX, ProfileiconY +ProfileiconHeight, white, smallFont, renderer);
renderText(textSettings, SettingsiconX, SettingsiconY +SettingsiconHeight, white, smallFont, renderer);
renderText(textCognitiveStats, CognitiveStatsiconX, CognitiveStatsiconY +CognitiveStatsiconHeight, white, smallFont, renderer);
renderText(textDataStats, DataStatsiconX , DataStatsiconY +DataStatsiconHeight, white, smallFont, renderer);
renderText(textTargets, TargetsiconX, TargetsiconY +TargetsiconHeight, white, smallFont, renderer);
renderText(textSystemHealth, SystemHealthiconX, SystemHealthiconY +SystemHealthiconHeight, white, smallFont, renderer);


// Cleanup smallFont
TTF_CloseFont(smallFont);



SDL_DestroyTexture(homeIconTexture);
SDL_DestroyTexture(profileIconTexture);
SDL_DestroyTexture(settingsIconTexture);
SDL_DestroyTexture(cognitiveStatsIconTexture);
SDL_DestroyTexture(dataStatsIconTexture);
SDL_DestroyTexture(targetsIconTexture);
SDL_DestroyTexture(systemHealthIconTexture);

// Quit SDL_image (somewhere in your cleanup code)
IMG_Quit();
    }

   virtual  void cleanup() override {
        // Implement cleanup logic if needed
    }
};





// MainDashboardState class
class MainDashboardScreenState : public NavigationMenu {
    private:
        std::string SearchElement;
        bool enteringSearchElement;



        int SearchboxWidth=500;
        int SearchboxHeight=30;
        int SearchboxX, SearchboxY;
      
        int textWidthSearch, textHeightSearch, textXSearch,textYSearch;

        int SearchiconWidth=22;
        int SearchiconHeight=22;
       int SearchiconX,SearchiconY;






 
// Text (e.g., articles, blog posts, web pages)
// PDFs (e.g., reports, research papers, manuals)
// Images (e.g., photos, graphics, illustrations)
// Videos (e.g., movies, tutorials, vlogs)
// Audio (e.g., podcasts, music, sound effects)
// Spreadsheets (e.g., data sheets, financial reports)
// Presentations (e.g., slideshows, pitch decks)
// Code (e.g., source code, scripts, software)
// 3D Models (e.g., CAD files, 3D renders)
// E-books (e.g., digital books, manuals)






int textWidthAll, textWidthText, textWidthPDFs, textWidthImages , textWidthVideos, textWidthAudio , textWidthSpreadsheets , textWidthPresentations , textWidthCode , textWidth3DModels , textWidthEbooks ;

int textHeightAll, textHeightText, textHeightPDFs, textHeightImages, textHeightVideos, textHeightAudio , textHeightSpreadsheets , textHeightPresentations , textHeightCode , textHeight3DModels , textHeightEbooks ;


int textXAll, textXText, textXPDFs,textXImages,textXVideos, textXAudio, textXSpreadsheets,textXPresentations , textXCode, textX3DModels,textXEbooks ;

int textYAll,textYText, textYPDFs, textYImages, textYVideos, textYAudio, textYSpreadsheets ,textYPresentations, textYCode, textY3DModels,textYEbooks ;




    public:
        MainDashboardScreenState(SDL_Window *window, SDL_Renderer *renderer, TTF_Font *digitalFont) : NavigationMenu(window, renderer, digitalFont),SearchElement(""),enteringSearchElement(true)
 
        {


           SDL_StartTextInput();
    }
    
    void handleEvents(SDL_Event& event) override {
        NavigationMenu::handleEvents(event);
        if (event.type == SDL_TEXTINPUT) {
        if (enteringSearchElement) {
            SearchElement += event.text.text;
        }}
        else if (event.type == SDL_KEYDOWN) {
        switch (event.key.keysym.sym) {
            case SDLK_BACKSPACE:
 if (enteringSearchElement && !SearchElement .empty()) {
                    SearchElement .pop_back();
                }
                break;
                // case SDLK_RETURN:
                // enter key would search for that data and bring that up but that would be implemented later on 
default:
                break;
        }
    }  else if (event.type == SDL_MOUSEBUTTONDOWN || event.type == SDL_FINGERDOWN) {
        int mouseX, mouseY;

        if (event.type == SDL_MOUSEBUTTONDOWN) {
            mouseX = event.button.x;
            mouseY = event.button.y;
        } else { // SDL_FINGERDOWN
            mouseX = event.tfinger.x * Width;
            mouseY = event.tfinger.y * Height;
        }

        std::cout << "Click at (" << mouseX << ", " << mouseY << ")" << std::endl;
 if (mouseX >= SearchboxX && mouseX <= SearchboxX + SearchboxWidth && mouseY >= SearchboxY && mouseY <= SearchboxY + SearchboxHeight) {
            enteringSearchElement = true;}
    }



//next i need to handle event clicks for different data types and that should be connected to some kind of fillter system to bring only that data for me 
    }
    
    void update() override {
         NavigationMenu:: update();
    }
    
    void render() override {
        NavigationMenu::render();
        SDL_Color white = {255, 255, 255, 255};
        SDL_Color grey = {100, 100, 100, 255};
        SDL_Color black = {0, 0, 0, 255};
        SDL_Color darkgreen = {0, 50, 0, 255};
        SDL_Color maroon = {128, 0, 0, 255};

        SearchboxY = ((Height - SearchboxHeight) / 2) - 250;
        textYSearch = SearchboxY;

        textYAll = SearchboxY + (Height / 17);
        textYText = SearchboxY + (Height / 17);
        textYPDFs = SearchboxY + (Height / 17);
        textYImages = SearchboxY + (Height / 17);
        textYVideos = SearchboxY + (Height / 17);

        textYAudio = SearchboxY + (Height / 17);
        textYSpreadsheets = SearchboxY + (Height / 17);
        textYPresentations = SearchboxY + (Height / 17);
        textYCode = SearchboxY + (Height / 17);
        textY3DModels = SearchboxY + (Height / 17);
        textYEbooks = SearchboxY + (Height / 17);

        // Calculate positions based on proportional spacing
        SearchiconY = SearchboxY + 3;

        std::string textSearch = "Search" + SearchElement;

        const char *textAll = "All";
        const char *textText = "Text";
        const char *textPDFs = "PDFs";
        const char *textImages = "Images";
        const char *textVideos = "Videos";
        const char *textAudio = " Audio";
        const char *textSpreadsheets = "Spreadsheets";
        const char *textPresentations = "Presentations";
        const char *textCode = " Code";
        const char *text3DModels = "3D Models";
        const char *textEbooks = "E-books ";

        TTF_SizeText(digitalFont, textSearch.c_str(), &textWidthSearch, &textHeightSearch);
        TTF_SizeText(digitalFont, textAll, &textWidthAll, &textHeightAll);
        TTF_SizeText(digitalFont, textText, &textWidthText, &textHeightText);
        TTF_SizeText(digitalFont, textPDFs, &textWidthPDFs, &textHeightPDFs);
        TTF_SizeText(digitalFont, textImages, &textWidthImages, &textHeightImages);
        TTF_SizeText(digitalFont, textVideos, &textWidthVideos, &textHeightVideos);
        TTF_SizeText(digitalFont, textAudio, &textWidthAudio, &textHeightAudio);
        TTF_SizeText(digitalFont, textSpreadsheets, &textWidthSpreadsheets, &textHeightSpreadsheets);
        TTF_SizeText(digitalFont, textPresentations, &textWidthPresentations, &textHeightPresentations);
        TTF_SizeText(digitalFont, textCode, &textWidthCode, &textHeightCode);
        TTF_SizeText(digitalFont, text3DModels, &textWidth3DModels, &textHeight3DModels);
        TTF_SizeText(digitalFont, textEbooks, &textWidthEbooks, &textHeightEbooks);

        SearchboxX = (Width - SearchboxWidth) / 2;
        ;
        SearchiconX = SearchboxX + SearchboxWidth - SearchiconWidth - 10;

        textXSearch = (Width - textWidthSearch) / 2;
        ;

        textXAll = SearchboxX + ((SearchboxWidth - textWidthAll) / 2) - 380;

        textXText = textXAll + textWidthAll + 10;
        textXPDFs = textXText + textWidthText + 10;
        textXImages = textXPDFs + textWidthPDFs + 10;
        textXVideos = textXImages + textWidthImages + 10;
        textXAudio = textXVideos + textWidthVideos + 10;
        textXSpreadsheets = textXAudio + textWidthAudio + 10;
        textXPresentations = textXSpreadsheets + textWidthSpreadsheets + 10;
        textXCode = textXPresentations + textWidthPresentations + 10;
        textX3DModels = textXCode + textWidthCode + 10;
        textXEbooks = textX3DModels + textWidth3DModels + 10;

        renderRoundedRect(renderer, SearchboxX, SearchboxY, SearchboxWidth, SearchboxHeight, radius, white);

        // Render Search
        if (enteringSearchElement && !SearchElement.empty())
        {
            renderText(SearchElement.c_str(), SearchboxX, SearchboxY, black, digitalFont, renderer);
    } else {

 if (SearchElement.empty()) {
         renderText("Search", textXSearch, textYSearch, grey, digitalFont, renderer);
    } else {
        renderText(SearchElement.c_str(), SearchboxX, SearchboxY, black, digitalFont, renderer);
    }
}

SDL_Texture* SearchIconTexture = loadTexture("C:/NEW/assets/searchiconn.png", renderer);
// SDL_Texture* BellIconTexture = loadTexture("C:/NEW/assets/bell.jpg", renderer);


 SDL_Rect Searchicon = {SearchiconX, SearchiconY, SearchiconWidth, SearchiconHeight};
 
       SDL_SetRenderDrawColor(renderer, 255, 255, 255, 255);
         SDL_RenderCopy(renderer,SearchIconTexture, NULL, &Searchicon);


 renderText(textAll, textXAll, textYAll, white, digitalFont, renderer);
renderText(textText, textXText, textYText, white, digitalFont, renderer);
renderText(textPDFs, textXPDFs, textYPDFs, white, digitalFont, renderer);
renderText(textImages, textXImages, textYImages, white, digitalFont, renderer);
renderText(textVideos, textXVideos, textYVideos, white, digitalFont, renderer);
renderText(textAudio, textXAudio, textYAudio, white, digitalFont, renderer);
renderText(textSpreadsheets, textXSpreadsheets, textYSpreadsheets, white, digitalFont, renderer);
renderText(textPresentations, textXPresentations, textYPresentations, white, digitalFont, renderer);
renderText(textCode, textXCode, textYCode, white, digitalFont, renderer);
renderText(text3DModels, textX3DModels, textY3DModels, white, digitalFont, renderer);
renderText(textEbooks, textXEbooks, textYEbooks, white, digitalFont, renderer);

SDL_DestroyTexture(SearchIconTexture);

// Quit SDL_image (somewhere in your cleanup code)
IMG_Quit();









        
       
    }
    void cleanup() override {
        NavigationMenu::cleanup();
    }
};



class Verification :public State  {
protected:

// SDL_Window* window;
//     SDL_Renderer* renderer;
//     TTF_Font* digitalFont;
    
  
 std::string   VerificationExpireMessage;
 std::string  VerificationIncorrectMessage; 
 std::string  VerificationSuccessMessage;


    SDL_Color VerificationMessageColor;  
     Uint32 VerificationMessageTime;  
    const Uint32 VERIFICATION_MESSAGE_DISPLAY_TIME = 2000;  // 2000 milliseconds = 2 second
    bool VerificationSuccess = false;

 bool renderExpireMessage, renderIncorrectMessage, renderSuccessMessage;


    SDL_Color white = {255, 255, 255, 255};
    SDL_Color grey = { 100, 100, 100, 255 };
    SDL_Color black = { 0, 0, 0, 255 };
    SDL_Color darkgreen = { 0, 50, 0, 255  }; 
    SDL_Color maroon = { 128, 0, 0, 255 };
 

std::string userInput,emailAddress, phoneNumber,GVCode,verificationCode ;

bool isEmailInput = false;

bool enteringEmail; 
bool enteringverificationCode;

int boxPadding = 20;



int textWidth1, textHeight1;
    int textWidth2a, textHeight2a;
    int textWidth2b, textHeight2b;
    int textWidth3, textHeight3;
    int textWidth4, textHeight4;
    int textWidth5, textHeight5;
    int textWidth6, textHeight6;
    int textWidth7, textHeight7;
    int textWidth8, textHeight8;
    int textWidthVerificationMessage, textHeightVerificationMessage;

    int textX1, textX2a,textX2b, textX3, textX4, textX5, textX6, textX7,textX8 ,textXVerificationMessage;
 int textY1, textY2a,textY2b, textY3, textY4, textY5, textY6, textY7,textY8, textYVerificationMessage;

// EmailBox;
// SendCodeBox;
// verificationCodeBox;
// Verify;
// supportBox;


int EmailBoxWidth=250;
int SendCodeBoxWidth=100;
int verificationCodeBoxWidth=250;
int VerifyWidth=100;
int supportBoxWidth=400;
int boxWidth=Width- 6* boxPadding;

int EmailBoxHeight=35;
int SendCodeBoxHeight=30;
int verificationCodeBoxHeight=35;
int VerifyHeight=30;
int supportBoxHeight=30;
int boxHeight= Height - 10* boxPadding;

int EmailBoxX;
int SendCodeBoxX;
int verificationCodeBoxX;
int VerifyX;
int supportBoxX;
int boxX;

int EmailBoxY;
int SendCodeBoxY;
int verificationCodeBoxY;
int VerifyY;
int supportBoxY;
int boxY;

public:

    Verification(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* digitalFont)
    : State(window, renderer, digitalFont),
      
          emailAddress(""), phoneNumber(""), verificationCode(""),  VerificationExpireMessage(""),  VerificationIncorrectMessage(""), VerificationSuccessMessage(""), 
          renderExpireMessage(false), 
      renderIncorrectMessage(false), 
      renderSuccessMessage(false), 
          enteringEmail(true), enteringverificationCode(false)
    {
        SDL_StartTextInput();
        // Initialize other necessary variables if needed
    }
virtual std::string getVerificationSuccessMessage() const = 0;
 virtual void updateVerificationMessage() {
    bool codeIsValid = validateVerificationCode(verificationCode, GVCode);
    bool codeIsExpired = checkCodeExpiration(verificationCode);

    renderExpireMessage = false;
    renderIncorrectMessage = false;
    renderSuccessMessage = false;

    if (codeIsExpired) {
        VerificationMessageColor = {128, 0, 0, 255};  // maroon
        VerificationMessageTime = SDL_GetTicks();
        VerificationSuccess = false;
        renderExpireMessage = true;
    } else if (!codeIsValid) {
        VerificationMessageColor = {128, 0, 0, 255};  // maroon
        VerificationMessageTime = SDL_GetTicks();
        VerificationSuccess = false;
        renderIncorrectMessage = true;
    } else {
        VerificationMessageColor = {0, 100, 0, 255};  // dark green
        VerificationMessageTime = SDL_GetTicks();
        VerificationSuccess = true;
        renderSuccessMessage = true;
        changeState(LOGIN_SCREEN);
    }
}
  virtual void handleEvents(SDL_Event& event)  {
    // Handle text input for email/phone and verification code
    if (event.type == SDL_TEXTINPUT) {
       std::cout << "Text Input Event: " << event.text.text << std::endl;
        if (enteringEmail) {
            userInput += event.text.text;
            emailAddress = userInput;
            //std::cout << "Email Address Input: " << emailAddress << std::endl;
        } else if (enteringverificationCode) {
            //std::cout << "enteringverificationCode: " << enteringverificationCode << std::endl;
            verificationCode += event.text.text;
            //std::cout << "Verification Code Input: " << verificationCode << std::endl;
        }
    }
else if (event.type == SDL_KEYDOWN) {
        if (event.key.keysym.sym == SDLK_BACKSPACE) {
            if (enteringEmail && !userInput.empty()) {
                userInput.pop_back();
                emailAddress = userInput;
            } else if (enteringverificationCode && !verificationCode.empty()) {
                verificationCode.pop_back();
            }
        }






        
         else if (event.key.keysym.sym == SDLK_RETURN) {

            if (enteringEmail && !userInput.empty()) {
                 std::cout << "Submitting Email Address: " << emailAddress << std::endl;
                 enteringEmail = false; 
                 enteringverificationCode = true; 
            } // Determine if the input is an email or phone number
                if (isEmail(userInput)) {
                    emailAddress = userInput;
                   GVCode = sendVerificationCodeToEmail(emailAddress);
                } else {
                    phoneNumber = userInput;
                   GVCode = sendVerificationCodeToPhone(phoneNumber);
                }
            } 
            else if (enteringverificationCode && !userInput.empty() && !verificationCode.empty()) {  
                
                
                std::cout << "Submitting Verification Code: " << verificationCode << std::endl;
                

                
       
                updateVerificationMessage(); // Update the verification message based on the code validation
            }
        }
    
            

    // Handle mouse and touch events
    if (event.type == SDL_MOUSEBUTTONDOWN || event.type == SDL_FINGERDOWN) {
        int mouseX, mouseY;

        if (event.type == SDL_MOUSEBUTTONDOWN) {
            mouseX = event.button.x;
            mouseY = event.button.y;
        } else { // SDL_FINGERDOWN
            mouseX = event.tfinger.x * Width;
            mouseY = event.tfinger.y * Height;
        }

        std::cout << "Click at (" << mouseX << ", " << mouseY << ")" << std::endl;

        // Email or Phone Input Box
        if (mouseX >= EmailBoxX && mouseX <= EmailBoxX + EmailBoxWidth && mouseY >= EmailBoxY && mouseY <= EmailBoxY + EmailBoxHeight) {
            enteringEmail = true;
            enteringverificationCode = false;
        } 
        
         if (mouseX >= verificationCodeBoxX && mouseX <= verificationCodeBoxX + verificationCodeBoxWidth && mouseY >= verificationCodeBoxY && mouseY <= verificationCodeBoxY + verificationCodeBoxHeight) {
            
            enteringverificationCode = true;
            enteringEmail = false;
        }

        // Send Code Button
        if (mouseX >= SendCodeBoxX && mouseX <= SendCodeBoxX + SendCodeBoxWidth && mouseY >= SendCodeBoxY && mouseY <= SendCodeBoxY + SendCodeBoxHeight) {
            //std::cout << "Send Code button clicked" << std::endl;

            if (isEmailInput) {
        GVCode =  sendVerificationCodeToEmail(emailAddress);
    } else {
        GVCode =  sendVerificationCodeToPhone(phoneNumber);
    }
        }


        // Resend Code Link
        if (mouseX >= textX7 && mouseX <= textX7 + textWidth7&& mouseY >= textY7 && mouseY <= textHeight7) {
            //std::cout << "Resend Code link clicked" << std::endl;

              if (isEmailInput) {
        GVCode =  sendVerificationCodeToEmail(emailAddress);
    } else {
        GVCode =  sendVerificationCodeToPhone(phoneNumber);
    }
        }

        // Support Link
        if (mouseX >= supportBoxX && mouseX <= supportBoxX + supportBoxWidth && mouseY >= supportBoxY && mouseY <= supportBoxY + supportBoxHeight) {
            std::cout << "Support link clicked" << std::endl;
            changeState(HELP_SCREEN); // Move to help screen
        }
    

// Verify Button
if (mouseX >= VerifyX && mouseX <= VerifyX + VerifyWidth && mouseY >= VerifyY && mouseY <= VerifyY + VerifyHeight) {
    std::cout << "Verify button clicked" << std::endl;

     updateVerificationMessage();
  

}}
  }


   virtual void update()override {
        // Update logic for Verification Screen if needed
    }

  virtual  void render(
        const char* text1,
        const char* text2a,
        const char* text2b,
        const std::string& text3,
        const char* text4,
        const std::string& text5,
        const char* text6,
        const char* text7,
        const char* text8 ,
        const std::string& VerificationExpireMessage,
        const std::string&VerificationIncorrectMessage,
        const std::string& VerificationSuccessMessage)  {

textY1 = boxY -30; 
    textY2a = boxY + (Height / 12) + 1;
    textY2b = boxY + (Height / 12) + 20;
    textY3 = boxY + (Height / 12) + 50;
    textY4 = boxY + (Height / 12) + 95;
    textY5 = boxY + (Height / 12) + 160;
    textY6 = boxY + (Height / 12) + 200;
    textY7 = boxY + (Height / 12) + 250;
    textY8 =  boxY + (Height / 12) + 300;
    textYVerificationMessage =  boxY + (Height / 12) + 30;

    
EmailBoxY = textY3;
SendCodeBoxY = textY4;
verificationCodeBoxY=textY5;
VerifyY=textY6;
supportBoxY=textY8;
boxY = (Height - boxHeight) / 2;




// Get the dimensions of the text
TTF_SizeText(digitalFont, text1, &textWidth1, &textHeight1);
TTF_SizeText(digitalFont, text2a, &textWidth2a, &textHeight2a);
TTF_SizeText(digitalFont, text2b, &textWidth2b, &textHeight2b);
TTF_SizeText(digitalFont, text3.c_str(), &textWidth3, &textHeight3);
TTF_SizeText(digitalFont, text4, &textWidth4, &textHeight4);
TTF_SizeText(digitalFont, text5.c_str(), &textWidth5, &textHeight5);
TTF_SizeText(digitalFont, text6, &textWidth6, &textHeight6);
TTF_SizeText(digitalFont, text7, &textWidth7, &textHeight7);
 TTF_SizeText(digitalFont, text8, &textWidth8, &textHeight8);


//  TTF_SizeText(digitalFont, VerificationExpireMessage.c_str(), &textWidthVerificationMessage, &textHeightVerificationMessage);
//  TTF_SizeText(digitalFont, VerificationIncorrectMessage.c_str(), &textWidthVerificationMessage, &textHeightVerificationMessage);
//  TTF_SizeText(digitalFont, VerificationSuccessMessage.c_str(), &textWidthVerificationMessage, &textHeightVerificationMessage);



 textX1 = (Width - textWidth1) / 2;
    textX2a= boxX + (boxWidth - textWidth2a) / 2;
    textX2b= boxX + (boxWidth - textWidth2b) / 2;
    textX3 = boxX + (boxWidth - textWidth3) / 2;
    textX4 = boxX + (boxWidth - textWidth4) / 2;
    textX5 = boxX + (boxWidth - textWidth5) / 2;
    textX6 = boxX + (boxWidth - textWidth6) / 2;
    textX7 = boxX + (boxWidth - textWidth7) / 2;
    textX8 = boxX + (boxWidth - textWidth8) / 2;
    textXVerificationMessage = boxX + (boxWidth - textWidthVerificationMessage) / 2;

   
EmailBoxX= boxX + (boxWidth - EmailBoxWidth) / 2;
SendCodeBoxX = boxX + (boxWidth - SendCodeBoxWidth) / 2;
verificationCodeBoxX=boxX + (boxWidth - verificationCodeBoxWidth) / 2;
VerifyX=boxX + (boxWidth - VerifyWidth) / 2;
supportBoxX=boxX + (boxWidth - supportBoxWidth) / 2;
boxX = (Width - boxWidth) / 2;



SDL_Rect outerBox = { boxX, boxY, boxWidth, boxHeight };
 // Set the color for the fill (black) and render the inside of the box
    SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
    SDL_RenderFillRect(renderer, &outerBox);

     renderRoundedRect(renderer, EmailBoxX, EmailBoxY, EmailBoxWidth, EmailBoxHeight, radius, white);
      
           renderRoundedRect(renderer,SendCodeBoxX, SendCodeBoxY, SendCodeBoxWidth,SendCodeBoxHeight, radius,darkgreen);
      
           renderRoundedRect(renderer, verificationCodeBoxX, verificationCodeBoxY, verificationCodeBoxWidth,verificationCodeBoxHeight, radius, white);
      
           renderRoundedRect(renderer, VerifyX, VerifyY, VerifyWidth,VerifyHeight, radius, darkgreen);
      
           renderRoundedRect(renderer, supportBoxX, supportBoxY, supportBoxWidth,supportBoxHeight, radius, grey);
      


// Render text inside boxes
    renderText(text1, textX1, textY1, white, digitalFont, renderer);
    renderText(text2a, textX2a, textY2a, grey, digitalFont, renderer);
    renderText(text2b, textX2b, textY2b, grey, digitalFont, renderer);
    renderText(text4, textX4, textY4, white, digitalFont, renderer); 
    renderText(text6, textX6, textY6, white, digitalFont, renderer); 
    renderText(text7, textX7, textY7, white, digitalFont, renderer); 
    renderText(text8, textX8, textY8, black, digitalFont, renderer); 
// Only render the relevant message based on the flags
    if (renderExpireMessage) {
        if (TTF_SizeText(digitalFont, VerificationExpireMessage.c_str(), &textWidthVerificationMessage, &textHeightVerificationMessage) == 0) {
            textXVerificationMessage = boxX + (boxWidth - textWidthVerificationMessage) / 2;
            renderText(VerificationExpireMessage, textXVerificationMessage, textYVerificationMessage, VerificationMessageColor, digitalFont, renderer);
        }
    } else if (renderIncorrectMessage) {
        if (TTF_SizeText(digitalFont, VerificationIncorrectMessage.c_str(), &textWidthVerificationMessage, &textHeightVerificationMessage) == 0) {
            textXVerificationMessage = boxX + (boxWidth - textWidthVerificationMessage) / 2;
            renderText(VerificationIncorrectMessage, textXVerificationMessage, textYVerificationMessage, VerificationMessageColor, digitalFont, renderer);
        }
    } else if (renderSuccessMessage) {
        if (TTF_SizeText(digitalFont, VerificationSuccessMessage.c_str(), &textWidthVerificationMessage, &textHeightVerificationMessage) == 0) {
            textXVerificationMessage = boxX + (boxWidth - textWidthVerificationMessage) / 2;
            renderText(VerificationSuccessMessage, textXVerificationMessage, textYVerificationMessage, VerificationMessageColor, digitalFont, renderer);
        }
    }




// Render email/phone input

// Check if the user input is an email
if (     enteringEmail &&      !userInput.empty()) {
    if (isEmail(userInput)) {
        emailAddress = userInput;
        isEmailInput = true;
        renderText( emailAddress.c_str(), EmailBoxX, EmailBoxY, black, digitalFont, renderer);
    } else {
        phoneNumber = userInput;
        isEmailInput = false;
        renderText( phoneNumber.c_str(), EmailBoxX, EmailBoxY, black, digitalFont, renderer);
    }
} else {

if (userInput.empty()) {
        renderText("Enter Email Address or Phone", textX3, textY3, grey, digitalFont, renderer);
    } else {
        if (isEmail(userInput)) {
        emailAddress = userInput;
        isEmailInput = true;
        renderText( emailAddress.c_str(), EmailBoxX, EmailBoxY, black, digitalFont, renderer);
    } else {
        phoneNumber = userInput;
        isEmailInput = false;
        renderText( phoneNumber.c_str(), EmailBoxX, EmailBoxY, black, digitalFont, renderer);
    }
    }  
}
   // RenderverificationCode
  if (enteringverificationCode && !verificationCode.empty()) {
        renderText(verificationCode.c_str(), verificationCodeBoxX, verificationCodeBoxY, black, digitalFont, renderer);
    } else {
         if (verificationCode.empty()) {
         renderText("Enter Verification Code", textX5, textY5, grey, digitalFont, renderer);
    } else {
        renderText(verificationCode.c_str(), verificationCodeBoxX, verificationCodeBoxY, black, digitalFont, renderer);
    }
       
    }
SDL_RenderPresent(renderer);
    }
    virtual void cleanup() override {
        // Implement cleanup logic if needed
    }
    // Method to verify if email and username belong to the same user
    bool verifyUser(const std::string& email, const std::string& username) {
        // Implementation to verify in your database or user management system
        // Return true if verified, false otherwise
        return true; // Replace with actual implementation
    }
     virtual ~Verification() = default;
};
class FVerificationScreenState :  public  Verification{
public:
 FVerificationScreenState (SDL_Window* window, SDL_Renderer* renderer, TTF_Font* digitalFont)
    : Verification (window ,renderer, digitalFont ) 
    {}
 std::string getVerificationSuccessMessage() const override {
        return "Verification successful! Your account has been created. You can now log in.";
    }
    void handleEvents(SDL_Event& event) override {
         Verification::handleEvents(event);}
    void update() override {
        Verification:: update ();
    }
    void render() override {
const char* text1 = "Please verify your email/phone to complete the sign-up process.";
const char* text2a = "We will send a verification code  ";
const char* text2b = " to the provided email or phone number";
std::string text3 = "Enter Email Address or Phone " + (isEmailInput ? emailAddress : phoneNumber);

const char* text4 = "Send Code"; // Send code button

std::string text5 = "Enter Verification Code" + verificationCode; // Input verification code
const char* text6 = "Verify"; // Verify button

const char* text7 = "Didn't receive the code? Resend"; // Resend link
const char* text8 = "Need help? Contact support"; // Contact support link
std::string VerificationExpireMessage="The code has expired. Please request a new code.";
std::string VerificationIncorrectMessage="The code you entered is incorrect. Please try again.";
std::string VerificationSuccessMessage= getVerificationSuccessMessage();;
Verification::render(text1, text2a, text2b, text3, text4, text5, text6, text7, text8, VerificationExpireMessage,VerificationIncorrectMessage,VerificationSuccessMessage);
    }

    void cleanup() override {
        Verification:: cleanup();
    }
};
class SVerificationScreenState :  public Verification{
public:
SVerificationScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* digitalFont)
    : Verification (window ,renderer, digitalFont )  
    {}
     std::string getVerificationSuccessMessage() const override {
        return "Verification successful! You can now reset your password.";
    }
    void handleEvents(SDL_Event& event) override {
       
       Verification::handleEvents(event);
    }
    void update() override {
        Verification:: update();
    }
    void render() override {
        const char *text1 = "Please verify your identity to reset your password.";
        const char *text2a = "We will send a verification code to this email or phone number ";
        const char *text2b = " if it matches an existing Neurabyte account.";
        std::string text3 = "Enter Email Address or Phone " + (isEmailInput ? emailAddress : phoneNumber);
        const char *text4 = "Send Code"; // Send code button
        std::string text5 = "Enter Verification Code" + verificationCode; // Input verification code
        const char *text6 = "Verify";                                     // Verify button
        const char *text7 = "Didn't receive the code? Resend"; // Resend link
        const char *text8 = "Need help? Contact support";      // Contact support link
std::string VerificationExpireMessage="The code has expired. Please request a new code.";
std::string VerificationIncorrectMessage="The code you entered is incorrect. Please try again.";
std::string VerificationSuccessMessage= getVerificationSuccessMessage();;
Verification::render(text1, text2a, text2b, text3, text4, text5, text6, text7, text8, VerificationExpireMessage,VerificationIncorrectMessage,VerificationSuccessMessage);
    }
    void cleanup() override {
        Verification:: cleanup();
    }
};
class PasswordResetScreenState : public State {
private:
     SDL_Color white = { 255, 255, 255, 255 };
    SDL_Color grey = { 100, 100, 100, 255 };
    SDL_Color black = { 0, 0, 0, 255 };
    SDL_Color darkgreen = { 0, 50, 0, 255  }; 
    SDL_Color maroon = { 128, 0, 0, 255 };
    std::string newPassword, confirmPassword;
    bool enteringNewPassword;
    bool enteringconfirmPassword;
public:
   PasswordResetScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* digitalFont)
        : State(window, renderer, digitalFont), newPassword(""),confirmPassword(""), enteringNewPassword(true), enteringconfirmPassword(false) {
        SDL_StartTextInput();
        // Initialize other necessary variables if needed
    }

    void handleEvents(SDL_Event& event) override {
      
    }

    void update() override {
        // Update logic for New Password Screen if needed
    }

    void render() override {
const char* text1 = "Please enter a new password for your account";
std::string text2 = "New Password: " + newPassword; // Input new password
std::string text3 = "Confirm New Password: " + confirmPassword; // Input confirm password
const char* text4 = "Reset Password"; // Reset password button

const char* text5 = "Back to Login"; // Back to login link




    }

    void cleanup() override {
        // Implement cleanup logic if needed
    }

    // Method to save new password to database
    void saveNewPasswordToDatabase(const std::string& newPassword) {
        // Implementation to update user's password in your database
    }
};
class HelpScreenState : public State {
private:
     SDL_Color white = { 255, 255, 255, 255 };
    SDL_Color grey = { 100, 100, 100, 255 };
    SDL_Color black = { 0, 0, 0, 255 };
    SDL_Color darkgreen = { 0, 50, 0, 255  }; 
    SDL_Color maroon = { 128, 0, 0, 255 };
 
public:
   HelpScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* digitalFont)
        : State(window, renderer, digitalFont){
        SDL_StartTextInput();
        // Initialize other necessary variables if needed
    }

    void handleEvents(SDL_Event& event) override {
      
    }

    void update() override {
        // Update logic for New Password Screen if needed
    }

    void render() override {
    }

    void cleanup() override {
        // Implement cleanup logic if needed
    }

   
};
class ProfileScreenState : public NavigationMenu{
private:
    SDL_Color white = { 255, 255, 255, 255 };
    SDL_Color grey = { 100, 100, 100, 255 };
    SDL_Color black = { 0, 0, 0, 255 };
    SDL_Color darkgreen = { 0, 50, 0, 255 };
    SDL_Color maroon = { 128, 0, 0, 255 };

public:
    ProfileScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* digitalFont)
        : NavigationMenu(window, renderer, digitalFont) {
        SDL_StartTextInput();
        // Initialize other necessary variables if needed
    }

    void handleEvents(SDL_Event& event) override {
         NavigationMenu::handleEvents(event);
    }

    void update() override {
       NavigationMenu:: update();
    }

    void render() override {
      NavigationMenu::render();
//okay so let's start building the prfile screen 
//because till now everything else is perfectly fine except that  therer is a little bit rendering problem sub kuch ow quality lag rha hy 
//2. sendinblue authentication ka masla
//3.sign up screen mn ek box sahi render nhi ho rha
//4. database sqlite sey change kr k kuch aur krna hy 











    }

    void cleanup() override {
         NavigationMenu::cleanup();
    }
};
//i think so settings screen should be a base class and all other screens should be dereived from it 
class SettingsScreenState : public NavigationMenu {
private:
    SDL_Color white = { 255, 255, 255, 255 };
    SDL_Color grey = { 100, 100, 100, 255 };
    SDL_Color black = { 0, 0, 0, 255 };
    SDL_Color darkgreen = { 0, 50, 0, 255 };
    SDL_Color maroon = { 128, 0, 0, 255 };

public:
    SettingsScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* digitalFont)
        : NavigationMenu(window, renderer, digitalFont) {
        SDL_StartTextInput();
        // Initialize other necessary variables if needed
    }

    void handleEvents(SDL_Event& event) override {
         NavigationMenu::handleEvents(event);
    }

    void update() override {
        NavigationMenu:: update();
    }

    void render() override {
         NavigationMenu::render();
    }

    void cleanup() override {
        NavigationMenu::cleanup();
    }
};

class CognitiveStatsScreenState : public NavigationMenu {
private:
    SDL_Color white = { 255, 255, 255, 255 };
    SDL_Color grey = { 100, 100, 100, 255 };
    SDL_Color black = { 0, 0, 0, 255 };
    SDL_Color darkgreen = { 0, 50, 0, 255 };
    SDL_Color maroon = { 128, 0, 0, 255 };

public:
    CognitiveStatsScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* digitalFont)
        : NavigationMenu(window, renderer, digitalFont) {
        SDL_StartTextInput();
        // Initialize other necessary variables if needed
    }

    void handleEvents(SDL_Event& event) override {
         NavigationMenu::handleEvents(event);
    }

    void update() override {
        NavigationMenu:: update();
    }

    void render() override {
         NavigationMenu::render();
    }

    void cleanup() override {
         NavigationMenu::cleanup();
    }
};

class DataStatsScreenState : public NavigationMenu {
private:
    SDL_Color white = { 255, 255, 255, 255 };
    SDL_Color grey = { 100, 100, 100, 255 };
    SDL_Color black = { 0, 0, 0, 255 };
    SDL_Color darkgreen = { 0, 50, 0, 255 };
    SDL_Color maroon = { 128, 0, 0, 255 };

public:
    DataStatsScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* digitalFont)
        : NavigationMenu(window, renderer, digitalFont) {
        SDL_StartTextInput();
        // Initialize other necessary variables if needed
    }

    void handleEvents(SDL_Event& event) override {
        NavigationMenu::handleEvents(event);
    }

    void update() override {
        NavigationMenu:: update();
    }

    void render() override {
         NavigationMenu::render();
    }

    void cleanup() override {
         NavigationMenu::cleanup();}
};

class TargetsScreenState : public NavigationMenu{
private:
    SDL_Color white = { 255, 255, 255, 255 };
    SDL_Color grey = { 100, 100, 100, 255 };
    SDL_Color black = { 0, 0, 0, 255 };
    SDL_Color darkgreen = { 0, 50, 0, 255 };
    SDL_Color maroon = { 128, 0, 0, 255 };

public:
    TargetsScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* digitalFont)
        : NavigationMenu(window, renderer, digitalFont) {
        SDL_StartTextInput();
        // Initialize other necessary variables if needed
    }

    void handleEvents(SDL_Event& event) override {
         NavigationMenu::handleEvents(event);
    }

    void update() override {
        NavigationMenu:: update();
    }

    void render() override {
         NavigationMenu::render();
    }

    void cleanup() override {
        NavigationMenu::cleanup();
    }
};

class SystemHealthScreenState : public NavigationMenu{
private:
    SDL_Color white = { 255, 255, 255, 255 };
    SDL_Color grey = { 100, 100, 100, 255 };
    SDL_Color black = { 0, 0, 0, 255 };
    SDL_Color darkgreen = { 0, 50, 0, 255 };
    SDL_Color maroon = { 128, 0, 0, 255 };

public:
    SystemHealthScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* digitalFont)
        : NavigationMenu(window, renderer, digitalFont) {
        SDL_StartTextInput();
        // Initialize other necessary variables if needed
    }

    void handleEvents(SDL_Event& event) override {
         NavigationMenu::handleEvents(event);
    }

    void update() override {
        NavigationMenu:: update();
    }

    void render() override {
         NavigationMenu::render();
    }

    void cleanup() override {
        NavigationMenu::cleanup();
    }
};







std::map<AppState, SDL_Color> backgroundColors = {
    {SPLASH_SCREEN, {0, 0, 0, 255}},        // Black
    {LOGIN_SCREEN,{50, 50, 50, 255}},    // Dark Grey
    {SIGNUP_SCREEN, {50, 50, 50, 255}},    // Dark Grey
    {MAIN_DASHBOARD, {50,50,50 ,255}},        // Black
    {F_VERIFICATION_SCREEN, {50, 50, 50, 255}},    // Dark Grey
    {S_VERIFICATION_SCREEN, {50, 50, 50, 255}},    // Dark Grey
    {PASSWORD_RESET_SCREEN, {50, 50, 50, 255}},    // Dark Grey
    {HELP_SCREEN, {50, 50, 50, 255}},    // Dark Grey
    
    {PROFILE_SCREEN, {50, 50, 50, 255}},    // Dark Grey
    {SETTINGS_SCREEN, {50, 50, 50, 255}},    // Dark Grey
    {COGNITIVE_STATS_SCREEN, {50, 50, 50, 255}},    // Dark Grey
    {DATA_STATS_SCREEN, {50, 50, 50, 255}},    // Dark Grey
    {TARGETS_SCREEN, {50, 50, 50, 255}},    // Dark Grey
    {SYSTEM_HEALTH_SCREEN, {50, 50, 50, 255}},    // Dark Grey
    
    // Add other colors for other states as needed
};



// Function to change the current state
void changeState(AppState newState) {
      std::cout << "Changing state to: " << newState << std::endl;
    
  // Clean up the current state
    if (currentStateInstance) {
        currentStateInstance->cleanup();
        currentStateInstance.reset();
    }


    switch (newState) {
        case SPLASH_SCREEN:
            currentStateInstance = std::make_unique<SplashScreenState>(window, renderer, digitalFont);
            break;
        case LOGIN_SCREEN:
            currentStateInstance = std::make_unique<LoginScreenState>(window, renderer, digitalFont);
            break;
        case SIGNUP_SCREEN:
            currentStateInstance = std::make_unique<SignupScreenState>(window, renderer, digitalFont);
            break;
        case MAIN_DASHBOARD:
            currentStateInstance = std::make_unique<MainDashboardScreenState>(window, renderer, digitalFont);
            break; 

         case F_VERIFICATION_SCREEN:
            currentStateInstance = std::make_unique<FVerificationScreenState>(window, renderer, digitalFont);
            break;
        case S_VERIFICATION_SCREEN:
            currentStateInstance = std::make_unique<SVerificationScreenState>(window, renderer, digitalFont);
            break;
         
        case PASSWORD_RESET_SCREEN:
            currentStateInstance = std::make_unique<PasswordResetScreenState>(window, renderer, digitalFont);
            break; 
        case HELP_SCREEN:
            currentStateInstance = std::make_unique<HelpScreenState>(window, renderer, digitalFont);
            break;
             case PROFILE_SCREEN:
            currentStateInstance = std::make_unique<ProfileScreenState>(window, renderer, digitalFont);
            break;
             case SETTINGS_SCREEN:
            currentStateInstance = std::make_unique<SettingsScreenState>(window, renderer, digitalFont);
            break;
             case COGNITIVE_STATS_SCREEN:
            currentStateInstance = std::make_unique<CognitiveStatsScreenState>(window, renderer, digitalFont);
            break;
             case DATA_STATS_SCREEN:
            currentStateInstance = std::make_unique<DataStatsScreenState>(window, renderer, digitalFont);
            break;
             case TARGETS_SCREEN:
            currentStateInstance = std::make_unique<TargetsScreenState>(window, renderer, digitalFont);
            break;
             case SYSTEM_HEALTH_SCREEN:
            currentStateInstance = std::make_unique<SystemHealthScreenState>(window, renderer, digitalFont);
            break;
        default:
            // Handle default case or error condition
            break;
    }
    // Change window title based on newState
    SDL_SetWindowTitle(window, screenNames[newState]);

 // Set the background color
    SDL_Color bgColor = backgroundColors[newState];
    SDL_SetRenderDrawColor(renderer, bgColor.r, bgColor.g, bgColor.b, bgColor.a);
    SDL_RenderClear(renderer);


    
    SDL_RenderPresent(renderer);



    currentState = newState;
}

// Main function
int main(int argc, char* argv[]) {





// Initialize SDL_image (somewhere in your initialization code)
if (IMG_Init(IMG_INIT_PNG) == 0) {
    std::cerr << "Failed to initialize SDL_image: " << IMG_GetError() << std::endl;
    return -1;
}

//intilaizing and opeening connecction ot sqlite database 
sqlite3* db;
int rc = sqlite3_open("C:/NEW/neurabyte.db", &db);

if (rc != SQLITE_OK) {
    std::cerr << "Error opening SQLite database: " << sqlite3_errmsg(db) << std::endl;
    // Handle error as needed (e.g., exit application)
}


// intialize libsodium
if (sodium_init() < 0) {
    std::cerr << "Failed to initialize libsodium" << std::endl;
    return -1; // or handle the error appropriately
}
    // Initialize SDL
    if (SDL_Init(SDL_INIT_EVERYTHING) != 0) {
        std::cerr << "SDL could not initialize! SDL_Error: " << SDL_GetError() << std::endl;
        return -1;
    }

    // Initialize SDL TTF
    if (TTF_Init() == -1) {
        std::cerr << "SDL TTF initialization failed: " << TTF_GetError() << std::endl;
        SDL_Quit();
        return -1;
    }

    // Create SDL window
    window = SDL_CreateWindow("SDL2 Window", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, Width,Height, SDL_WINDOW_RESIZABLE | SDL_WINDOW_SHOWN);
    if (!window) {
        std::cerr << "Window could not be created! SDL_Error: " << SDL_GetError() << std::endl;
        TTF_Quit();
        SDL_Quit();
        return -1;
    }

    // Create SDL renderer
    renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!renderer) {
        std::cerr << "Failed to create SDL renderer: " << SDL_GetError() << std::endl;
        SDL_DestroyWindow(window);
        TTF_Quit();
        SDL_Quit();
        return -1;
    }

    // Load Digital-7 font
    digitalFont = TTF_OpenFont("C:/NEW/assets/Nunito-Regular.ttf", 18);
    if (!digitalFont) {
        std::cerr << "Failed to load font: " << TTF_GetError() << std::endl;
        SDL_DestroyRenderer(renderer);
        SDL_DestroyWindow(window);
        TTF_Quit();
        SDL_Quit();
        return -1;
    }

// Initialize the database
    if (!initializeDatabase("C:/NEW/neurabyte.db")) { // Path provided here
        std::cerr << "Failed to initialize database." << std::endl;
        SDL_DestroyRenderer(renderer);
        SDL_DestroyWindow(window);
        TTF_Quit();
        SDL_Quit();
        return 1;
    }

  // Initialize currentUser
currentUser = std::make_unique<User>("default_email","default_username", "default_password" );

// Change state to SPLASH_SCREEN
changeState(SPLASH_SCREEN);
    // Initialize start time
    startTime = SDL_GetTicks();

    // Event loop
    bool quit = false;
    SDL_Event e;
    
    while (!quit) {
        while (SDL_PollEvent(&e) != 0) {
            if (e.type == SDL_QUIT) {
                quit = true;
            } else if (e.type == SDL_WINDOWEVENT) {
                switch (e.window.event) {
                    case SDL_WINDOWEVENT_RESIZED:
                        // Handle window resize event
                        Width = e.window.data1;
                        Height = e.window.data2;
                        // Optionally handle other aspects of resizing
                        break;
                    default:
                        break;
                }
            } else {
                currentStateInstance->handleEvents(e);
            }
        }

        // // Clear the screen
        SDL_Color bgColor = backgroundColors[currentState];
        SDL_SetRenderDrawColor(renderer, bgColor.r, bgColor.g, bgColor.b, bgColor.a);
        SDL_RenderClear(renderer); 
        
        //Update and render current state
        currentStateInstance->update();

        if (currentStateInstance) {
            currentStateInstance->render(); }

        // Present renderer
        SDL_RenderPresent(renderer);
    }

    // Cleanup resources
sqlite3_close(db);

    TTF_CloseFont(digitalFont);
    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    TTF_Quit();
    SDL_Quit();

    return 0;
}

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
#include <algorithm> // Including  this header for std::max
//#include <nfd.h> // Include native file dialog library


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
    PROFILE_SCREEN,
    F_VERIFICATION_SCREEN,
    PROFILE_UPDATE_SCREEN,
    SETTINGS_SCREEN,
    COGNITIVE_STATS_SCREEN,
    DATA_STATS_SCREEN,
    TARGETS_SCREEN,
    SYSTEM_HEALTH_SCREEN,
CONSENT_FORMS_SCREEN ,
LICENSE_AGREEMENTS_SCREEN,
TERMS_OF_SERVICE_SCREEN
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
    "Profile Screen",
    "F Verification Screen",
"Profile Update Screen State",
"Settings Screen",
"Cognitive Stats Scren",
"Data Stats Screen",
"Targets Screen",
"System Health Screen",
"Consent Forms Screen",
"License Agreements Screen",
"Terms Of Service Screen"


};

// Globals
int Width = 800;
int Height = 600;
int boxWidth = Width - 53;
const int offset=20;  


 int boxPadding;
 SDL_Window *window = nullptr;
 SDL_Renderer *renderer = nullptr;
 TTF_Font *NunitoFont = nullptr;
 TTF_Font *NimbusRomFont= nullptr;
 std::unique_ptr<User> currentUser = nullptr;
 AppState currentState = SPLASH_SCREEN;
 std::unique_ptr<State> currentStateInstance;
 Uint32 startTime = 0;

 void changeState(AppState newState);
 // keep in mind GVCode (Generated Verification Code) and verificationCode (User-entered Code)

 SDL_Texture *loadTexture(const std::string &path, SDL_Renderer *renderer)
 {
     SDL_Texture *newTexture = nullptr;
     SDL_Surface *loadedSurface = IMG_Load(path.c_str());
     if (loadedSurface == nullptr)
     {
         std::cerr << "Unable to load image " << path << "! SDL_image Error: " << IMG_GetError() << std::endl;
     }
     else
     {
         newTexture = SDL_CreateTextureFromSurface(renderer, loadedSurface);
         if (newTexture == nullptr)
         {
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
// Function to draw a circle
void DrawCircle(SDL_Renderer* renderer, int centerX, int centerY, int circleradius) {
    int x = circleradius;
    int y = 0;
    int err = 0;

    while (x >= y) {
        // Draw the points in all octants
        SDL_RenderDrawPoint(renderer, centerX + x, centerY + y); // Octant 1
        SDL_RenderDrawPoint(renderer, centerX + y, centerY + x); // Octant 2
        SDL_RenderDrawPoint(renderer, centerX - y, centerY + x); // Octant 3
        SDL_RenderDrawPoint(renderer, centerX - x, centerY + y); // Octant 4
        SDL_RenderDrawPoint(renderer, centerX - x, centerY - y); // Octant 5
        SDL_RenderDrawPoint(renderer, centerX - y, centerY - x); // Octant 6
        SDL_RenderDrawPoint(renderer, centerX + y, centerY - x); // Octant 7
        SDL_RenderDrawPoint(renderer, centerX + x, centerY - y); // Octant 8

        if (err <= 0) {
            y += 1;
            err += 2 * y + 1;
        }

        if (err > 0) {
            x -= 1;
            err -= 2 * x + 1;
        }
    }
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
    

sqlite3* db;

// Function to initialize the database and create tables
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
        sqlite3_close(db);
        db = nullptr; // Ensure db is set to nullptr if there is an error
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
        sqlite3_close(db);
        db = nullptr; // Ensure db is set to nullptr if there is an error
        return false;
    }

    // Create user_agreements table
    const char* createUserAgreementsTableSQL = R"(
        CREATE TABLE IF NOT EXISTS user_agreements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email_address TEXT NOT NULL,
            consent_forms INTEGER NOT NULL,
            license_agreements INTEGER NOT NULL,
            terms_of_service INTEGER NOT NULL
        );
    )";

    if (sqlite3_exec(db, createUserAgreementsTableSQL, nullptr, nullptr, &errorMessage) != SQLITE_OK) {
        std::cerr << "SQL error creating user_agreements table: " << errorMessage << std::endl;
        sqlite3_free(errorMessage);
        sqlite3_close(db);
        db = nullptr; // Ensure db is set to nullptr if there is an error
        return false;
    }

    // Leave the database connection open for later use
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


























bool insertUser(sqlite3* db,const User &user);
void setCurrentUser(const std::string &emailAddress, const std::string &username, const std::string &hashedPassword);
bool emailExists(const std::string &emailAddress);

void saveAgreementsToDatabase(sqlite3 *db, const User &user, bool isCheckbox1Checked, bool isCheckbox2Checked, bool isCheckbox3Checked);

void CreateUser(sqlite3* db, const std::string& username, const std::string& emailAddress, const std::string& password) {
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
    if (!insertUser(db, newUser)) {
        std::cerr << "Error: Failed to save user to database." << std::endl;
    } else {
        std::cout << "User created successfully." << std::endl;
        // Set the current user
        setCurrentUser(emailAddress, username, hashedPassword);
    }
}
bool insertUser(sqlite3* db, const User& user) {
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
    if (db == nullptr) {
        std::cerr << "Database connection is null." << std::endl;
        return true; // Assume email exists to prevent further errors
    }

    sqlite3_stmt* stmt;
    const char* sql = "SELECT COUNT(*) FROM users WHERE emailAddress = ?";

    // Prepare the SQL statement
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return true; // Assume email exists to prevent further errors
    }

    // Bind the parameter
    sqlite3_bind_text(stmt, 1, emailAddress.c_str(), -1, SQLITE_STATIC);

    // Execute the statement
    int result = sqlite3_step(stmt);
    bool exists = (result == SQLITE_ROW && sqlite3_column_int(stmt, 0) > 0);

    // Finalize the statement
    sqlite3_finalize(stmt);

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
    

    // If execution reaches here, login failed
    return false;
}
// Function to detect if the input is an email
bool isEmail(const std::string& input) {
    const std::regex pattern("[\\w.%+-]+@[\\w.-]+\\.[a-zA-Z]{2,}");
    return std::regex_match(input, pattern);
}



// Function to save agreements to the database
void saveAgreementsToDatabase(sqlite3* db, const User& user, bool isCheckbox1Checked, bool isCheckbox2Checked, bool isCheckbox3Checked) {
    if (db == nullptr) {
        std::cerr << "Database connection is null." << std::endl;
        return;
    }

    std::string query = "INSERT INTO user_agreements (username, email_address, consent_forms, license_agreements, terms_of_service) VALUES (?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt;
    int result = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    if (result != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return;
    }

    // Use getters to retrieve user data
    sqlite3_bind_text(stmt, 1, user.getUsername().c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user.getEmailAddress().c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, isCheckbox1Checked ? 1 : 0);
    sqlite3_bind_int(stmt, 4, isCheckbox2Checked ? 1 : 0);
    sqlite3_bind_int(stmt, 5, isCheckbox3Checked ? 1 : 0);

    result = sqlite3_step(stmt);
    if (result != SQLITE_DONE) {
        std::cerr << "Failed to insert data: " << sqlite3_errmsg(db) << std::endl;
    }

    sqlite3_finalize(stmt);
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
    sqlite3* db ;
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
       

        return isExpired;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        if (stmt) sqlite3_finalize(stmt);
        if (db) sqlite3_close(db);
        return false;
    }
}



void renderTextUnderlined(const char* text, int x, int y, SDL_Color color, TTF_Font* font, SDL_Renderer* renderer) {
    // Set the font style to underline
    TTF_SetFontStyle(font, TTF_STYLE_UNDERLINE);

    // Create a surface from the text
    SDL_Surface* textSurface = TTF_RenderText_Blended(font, text, color);
    if (textSurface) {
        // Create a texture from the surface
        SDL_Texture* textTexture = SDL_CreateTextureFromSurface(renderer, textSurface);
        if (textTexture) {
            // Get the dimensions of the text
            int textWidth = textSurface->w;
            int textHeight = textSurface->h;

            // Define the destination rectangle for rendering the text
            SDL_Rect renderQuad = { x, y, textWidth, textHeight };

            // Render the text
            SDL_RenderCopy(renderer, textTexture, NULL, &renderQuad);

            // Destroy the texture
            SDL_DestroyTexture(textTexture);
        }

        // Free the surface
        SDL_FreeSurface(textSurface);
    }

    // Reset the font style to normal (remove underline)
    TTF_SetFontStyle(font, TTF_STYLE_NORMAL);
}
















// Abstract class State
class State {
public:
    SDL_Window* window;
    SDL_Renderer* renderer;
    TTF_Font* NunitoFont;
    

    State(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* NunitoFont)
        : window(window), renderer(renderer), NunitoFont(NunitoFont) {}
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
    SplashScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* NunitoFont):State(window ,renderer, NunitoFont ) {
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
    TTF_SizeText(NunitoFont, "NEURABYTE", &textWidth, &textHeight);


int textX = (Width-textWidth) / 2; // Center horizontally
    int textY = (Height-textHeight )/ 2; // Center vertically

        renderText("NEURABYTE",  textX, textY, white, NunitoFont, renderer);
    }
void cleanup() override {
        // Implement cleanup logic 
    }

};
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
    int checkboxSize=20;

   
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


int checkboxX;
int tickStartX ;
int tickMiddleX ;
int tickEndX;
    
    


public:
    LoginScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* NunitoFont):State(window ,renderer, NunitoFont )
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
             case SDLK_DOWN:
                if (enteringUsername) {
                    enteringUsername = false;
                    enteringpassword = true;
                }
                break;

            case SDLK_UP:
                if (enteringpassword) {
                    enteringpassword = false;
                    enteringUsername = true;
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
 tickStartY = checkboxY + checkboxSize / 2+ checkboxSize / 4;
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
TTF_SizeText(NunitoFont, text1, &textWidth1, &textHeight1);
TTF_SizeText(NunitoFont, text2, &textWidth2, &textHeight2);
TTF_SizeText(NunitoFont, text3.c_str(), &textWidth3, &textHeight3);
TTF_SizeText(NunitoFont, text4.c_str(), &textWidth4, &textHeight4);
TTF_SizeText(NunitoFont, text5, &textWidth5, &textHeight5);
TTF_SizeText(NunitoFont, text6, &textWidth6, &textHeight6);
TTF_SizeText(NunitoFont, text7, &textWidth7, &textHeight7);
 TTF_SizeText(NunitoFont, text8, &textWidth8, &textHeight8);



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
    renderText(text1, textX1, textY1, white, NunitoFont, renderer); // Login to Continue
    renderText(text2, textX2, textY2, white, NunitoFont, renderer); // NEURABYTE



 renderText(text5, textX5, textY5, white, NunitoFont, renderer); // Login button
    renderText(text6, textX6, textY6, white, NunitoFont, renderer); // Forgot password link
    renderText(text7, textX7, textY7, white, NunitoFont, renderer); // Sign-up link
renderText(text8, textX8 + checkboxSize + 10, textY8, white, NunitoFont, renderer);

int const offset = 20;

// Render user ID
if (enteringUsername && !username.empty())
{
    renderText(username.c_str(), usernameBoxX+ offset, usernameBoxY, black, NunitoFont, renderer);
    } else {

 if (username.empty()) {
         renderText("User ID ", textX3, textY3, grey, NunitoFont, renderer);
    } else {
        renderText(username.c_str(), usernameBoxX+ offset, usernameBoxY, black, NunitoFont, renderer);
    }
}
    

   // Render password
if (enteringpassword && !password.empty()) {
    renderText((isPasswordVisible ? password : std::string(password.size(), '*')).c_str(), passwordBoxX+ offset, passwordBoxY, black, NunitoFont, renderer);
} else {
    if (password.empty()) {
        renderText("Password ", textX4, textY4, grey, NunitoFont, renderer);
    } else {
        renderText((isPasswordVisible ? password : std::string(password.size(), '*')).c_str(), passwordBoxX+ offset, passwordBoxY, black, NunitoFont, renderer);
    }
}

 if (!loginMessage.empty()) {
        int loginMessageWidth, loginMessageHeight;
        TTF_SizeText(NunitoFont, loginMessage.c_str(), &loginMessageWidth, &loginMessageHeight);
        int loginMessageX = (Width - loginMessageWidth) / 2;
        int loginMessageY = textY2 + textHeight2; 

        renderText(loginMessage.c_str(), loginMessageX, loginMessageY, loginMessageColor, NunitoFont, renderer);

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
    SignupScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* NunitoFont):State(window ,renderer, NunitoFont ),emailAddress(""), username(""), password(""), reconfirmedPassword(""),
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
        saveUserDataToDatabase(db); 


        changeState(F_VERIFICATION_SCREEN);
    }
    break;
case SDLK_DOWN:
    if (enteringemailAddress) {
        enteringemailAddress = false;
        enteringUsername = true;
    } else if (enteringUsername) {
        enteringUsername = false;
        enteringpassword = true;
    } else if (enteringpassword) {
        enteringpassword = false;
        enteringreconfirmedPassword = true;
    }
    break;
case SDLK_UP:
    if (enteringreconfirmedPassword) {
        enteringreconfirmedPassword = false;
        enteringpassword = true;
    } else if (enteringpassword) {
        enteringpassword = false;
        enteringUsername = true;
    } else if (enteringUsername) {
        enteringUsername = false;
        enteringemailAddress = true;
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
              saveUserDataToDatabase( db); 
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
TTF_SizeText(NunitoFont, text1, &textWidth1, &textHeight1);
TTF_SizeText(NunitoFont, text2, &textWidth2, &textHeight2);
TTF_SizeText(NunitoFont, text3.c_str(), &textWidth3, &textHeight3);
TTF_SizeText(NunitoFont, text4.c_str(), &textWidth4, &textHeight4);


TTF_SizeText(NunitoFont, text5.c_str(), &textWidth5, &textHeight5);
TTF_SizeText(NunitoFont, text6.c_str(), &textWidth6, &textHeight6);
TTF_SizeText(NunitoFont, text7, &textWidth7, &textHeight7);
 TTF_SizeText(NunitoFont, text8a, &textWidth8a, &textHeight8a);
 TTF_SizeText(NunitoFont, text8b, &textWidth8b, &textHeight8b);
 TTF_SizeText(NunitoFont, text9, &textWidth9, &textHeight9);



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


        renderText(text1, textX1, textY1, white, NunitoFont, renderer);
        renderText(text2, textX2, textY2, white, NunitoFont, renderer);
        renderText(text7, textX7, textY7, white, NunitoFont, renderer);
        renderText(text8a, textX8a, textY8a, grey,NunitoFont, renderer);
        renderText(text8b, textX8b, textY8b, grey, NunitoFont, renderer);
        renderText(text9, textX9, textY9, white, NunitoFont, renderer);
       

  
// Render email address
if (enteringemailAddress && !emailAddress.empty()) {
    renderText(emailAddress.c_str(), emailboxX, emailboxY, black, NunitoFont, renderer);
} else {
    // Render placeholder text only if emailAddress is empty
    if (emailAddress.empty()) {
        renderText("Email Address ", textX3, textY3, grey, NunitoFont, renderer);
    } else {
        renderText(emailAddress.c_str(), emailboxX, emailboxY, black, NunitoFont, renderer);
    }
}


  


    // Render user ID
    if (enteringUsername && !username.empty()) {
        renderText(username.c_str(), usernameboxX, usernameboxY, black, NunitoFont, renderer);
    } else {

 if (username.empty()) {
         renderText("User ID ", textX4, textY4, grey, NunitoFont, renderer);
    } else {
        renderText(username.c_str(), usernameboxX, usernameboxY, black, NunitoFont, renderer);
    }
}
    

    // Render password
    if (enteringpassword && !password.empty()) {
        renderText(password.c_str(), PasswordboxX, PasswordboxY, black, NunitoFont, renderer);
    } else {
         if (password.empty()) {
            
        renderText("Password ", textX5, textY5, grey, NunitoFont, renderer);
    } else {
       renderText(password.c_str(), PasswordboxX, PasswordboxY, black, NunitoFont, renderer);
    }
}
   

    // Render reconfirm password
    if (enteringreconfirmedPassword && !reconfirmedPassword.empty()) {
        renderText(reconfirmedPassword.c_str(), reconfirmpasswordboxX, reconfirmpasswordboxY, black, NunitoFont, renderer);
    } else {

         if (reconfirmedPassword.empty()) {
           
        renderText("Reconfirm Password ", textX6, textY6, grey, NunitoFont, renderer);
        }else {
         renderText(reconfirmedPassword.c_str(), reconfirmpasswordboxX, reconfirmpasswordboxY, black, NunitoFont, renderer);
    }
}
    

   

    }

    
    void cleanup() override {
        // Implement cleanup logic 
    }

// Method to save user data to database
 // Method to save user data to database
void saveUserDataToDatabase(sqlite3* db) {
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
    if (insertUser(db, newUser)) {
        std::cout << "User registered successfully." << std::endl;
    } else {
        std::cerr << "Error: Failed to register user." << std::endl;
    }
}
};

class NavigationMenu : public State {
protected:
int scrollOffsetY = 0;
int maxScrollOffset = 0;


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

SDL_Rect Bellicon;
SDL_Rect Searchicon;
SDL_Rect Homeicon;
SDL_Rect Profileicon;
SDL_Rect Settingsicon;
SDL_Rect CognitiveStatsicon;
SDL_Rect DataStatsicon;
SDL_Rect Targetsicon;
SDL_Rect SystemHealthicon;



SDL_Rect outerBox ;
int boxWidth;
int boxHeight ;
int boxY ;
int boxX ;








public:
    NavigationMenu(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* NunitoFont)
        : State(window, renderer, NunitoFont) {
        SDL_StartTextInput();
        // Initialize other necessary variables if needed
    }

    virtual void handleEvents(SDL_Event& event) override {
  if (event.type == SDL_MOUSEWHEEL) {
        // Scrolling up
        if (event.wheel.y > 0) {
            scrollOffsetY -= 100; // Scroll speed
            if (scrollOffsetY < 0) scrollOffsetY = 0;
        }
        // Scrolling down
        else if (event.wheel.y < 0) {
            scrollOffsetY += 100; // Scroll speed
            if (scrollOffsetY > maxScrollOffset) scrollOffsetY = maxScrollOffset;
        }
    }

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
    boxHeight = Height*7;
       maxScrollOffset = boxHeight ; 
// Set the position for the box
    boxY = 0 - scrollOffsetY;
 boxX = 53;
 boxWidth = Width-53;
  
 SDL_Rect outerBox = {boxX, boxY, boxWidth, boxHeight};
 // Set the color for the fill (black) and render the inside of the box

    SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);
    

    SDL_RenderFillRect(renderer, &outerBox);

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

TTF_SizeText(NunitoFont, textHome, &textWidthHome, &textHeightHome);
TTF_SizeText(NunitoFont, textProfile, &textWidthProfile, &textHeightProfile);
TTF_SizeText(NunitoFont, textSettings, &textWidthSettings, &textHeightSettings);
TTF_SizeText(NunitoFont, textCognitiveStats, &textWidthCognitiveStat, &textHeightCognitiveStat);
TTF_SizeText(NunitoFont, textDataStats, &textWidthDataStats, &textHeightDataStats);
TTF_SizeText(NunitoFont, textTargets, &textWidthTargets, &textHeightTargets);
TTF_SizeText(NunitoFont, textSystemHealth, &textWidthSystemHealth, &textHeightSystemHealth);


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

        int BelliconWidth = 20;
        int BelliconHeight = 20;
        int BelliconX, BelliconY;

        int SearchiconWidth=22;
        int SearchiconHeight=22;
       int SearchiconX,SearchiconY;












int textWidthAll, textWidthText, textWidthPDFs, textWidthImages , textWidthVideos, textWidthAudio , textWidthSpreadsheets , textWidthPresentations , textWidthCode , textWidth3DModels , textWidthEbooks ;

int textHeightAll, textHeightText, textHeightPDFs, textHeightImages, textHeightVideos, textHeightAudio , textHeightSpreadsheets , textHeightPresentations , textHeightCode , textHeight3DModels , textHeightEbooks ;


int textXAll, textXText, textXPDFs,textXImages,textXVideos, textXAudio, textXSpreadsheets,textXPresentations , textXCode, textX3DModels,textXEbooks ;

int textYAll,textYText, textYPDFs, textYImages, textYVideos, textYAudio, textYSpreadsheets ,textYPresentations, textYCode, textY3DModels,textYEbooks ;




    public:
        MainDashboardScreenState(SDL_Window *window, SDL_Renderer *renderer, TTF_Font *NunitoFont) : NavigationMenu(window, renderer, NunitoFont),SearchElement(""),enteringSearchElement(true)
 
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

        SearchboxY = (((Height - SearchboxHeight) / 2) - 250)- scrollOffsetY;
        textYSearch = (SearchboxY)-scrollOffsetY;

        textYAll = (SearchboxY + (Height / 17))- scrollOffsetY;
        textYText = (SearchboxY + (Height / 17))- scrollOffsetY;
        textYPDFs = (SearchboxY + (Height / 17))- scrollOffsetY;
        textYImages = (SearchboxY + (Height / 17))- scrollOffsetY;
        textYVideos = (SearchboxY + (Height / 17))- scrollOffsetY;

        textYAudio = (SearchboxY + (Height / 17))- scrollOffsetY;
        textYSpreadsheets = (SearchboxY + (Height / 17))- scrollOffsetY;
        textYPresentations = (SearchboxY + (Height / 17))- scrollOffsetY;
        textYCode = (SearchboxY + (Height / 17))- scrollOffsetY;
        textY3DModels = (SearchboxY + (Height / 17))- scrollOffsetY;
        textYEbooks = (SearchboxY + (Height / 17))- scrollOffsetY;

        // Calculate positions based on proportional spacing
        SearchiconY =( SearchboxY + 3)- scrollOffsetY;
        BelliconY =  (((Height - SearchboxHeight) / 2) - 242)- scrollOffsetY;
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

        TTF_SizeText(NunitoFont, textSearch.c_str(), &textWidthSearch, &textHeightSearch);
        TTF_SizeText(NunitoFont, textAll, &textWidthAll, &textHeightAll);
        TTF_SizeText(NunitoFont, textText, &textWidthText, &textHeightText);
        TTF_SizeText(NunitoFont, textPDFs, &textWidthPDFs, &textHeightPDFs);
        TTF_SizeText(NunitoFont, textImages, &textWidthImages, &textHeightImages);
        TTF_SizeText(NunitoFont, textVideos, &textWidthVideos, &textHeightVideos);
        TTF_SizeText(NunitoFont, textAudio, &textWidthAudio, &textHeightAudio);
        TTF_SizeText(NunitoFont, textSpreadsheets, &textWidthSpreadsheets, &textHeightSpreadsheets);
        TTF_SizeText(NunitoFont, textPresentations, &textWidthPresentations, &textHeightPresentations);
        TTF_SizeText(NunitoFont, textCode, &textWidthCode, &textHeightCode);
        TTF_SizeText(NunitoFont, text3DModels, &textWidth3DModels, &textHeight3DModels);
        TTF_SizeText(NunitoFont, textEbooks, &textWidthEbooks, &textHeightEbooks);

        SearchboxX = (Width - SearchboxWidth) / 2;
        
        SearchiconX = SearchboxX + SearchboxWidth - SearchiconWidth - 10;
BelliconX=(Width - BelliconWidth) ;
        
        textXSearch = (Width - textWidthSearch) / 2;
        ;

       // Calculate the position relative to Searchbox
int textXRelative = SearchboxX + ((SearchboxWidth - textWidthAll) / 2) - 380;

// Clamp the position to ensure it falls within the box
textXAll = std::max(boxX, std::min(textXRelative, boxX + boxWidth - textWidthAll));


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

        renderRoundedRect(renderer, SearchboxX, SearchboxY- scrollOffsetY, SearchboxWidth, SearchboxHeight, radius, white);

        // Render Search
        if (enteringSearchElement && !SearchElement.empty())
        {
            renderText(SearchElement.c_str(), SearchboxX, SearchboxY- scrollOffsetY, black, NunitoFont, renderer);
    } else {

 if (SearchElement.empty()) {
         renderText("Search", textXSearch, textYSearch- scrollOffsetY, grey, NunitoFont, renderer);
    } else {
        renderText(SearchElement.c_str(), SearchboxX, SearchboxY- scrollOffsetY, black, NunitoFont, renderer);
    }
}

SDL_Texture* SearchIconTexture = loadTexture("C:/NEW/assets/searchiconn.png", renderer);
 SDL_Texture* BellIconTexture = loadTexture("C:/NEW/assets/bell.jpg", renderer);


 SDL_Rect Searchicon = {SearchiconX, SearchiconY- scrollOffsetY, SearchiconWidth, SearchiconHeight};
 
       SDL_SetRenderDrawColor(renderer, 255, 255, 255, 255);
         SDL_RenderCopy(renderer,SearchIconTexture, NULL, &Searchicon);





 SDL_Rect Bellicon = {BelliconX, BelliconY- scrollOffsetY, BelliconWidth, BelliconHeight};
 
       SDL_SetRenderDrawColor(renderer, 255, 255, 255, 255);
         SDL_RenderCopy(renderer,BellIconTexture, NULL, &Bellicon);
 renderText(textAll, textXAll, textYAll- scrollOffsetY, white, NunitoFont, renderer);
renderText(textText, textXText, textYText- scrollOffsetY, white, NunitoFont, renderer);
renderText(textPDFs, textXPDFs, textYPDFs- scrollOffsetY, white, NunitoFont, renderer);
renderText(textImages, textXImages, textYImages- scrollOffsetY, white, NunitoFont, renderer);
renderText(textVideos, textXVideos, textYVideos- scrollOffsetY, white, NunitoFont, renderer);
renderText(textAudio, textXAudio, textYAudio- scrollOffsetY, white, NunitoFont, renderer);
renderText(textSpreadsheets, textXSpreadsheets, textYSpreadsheets- scrollOffsetY, white, NunitoFont, renderer);
renderText(textPresentations, textXPresentations, textYPresentations- scrollOffsetY, white, NunitoFont, renderer);
renderText(textCode, textXCode, textYCode- scrollOffsetY, white, NunitoFont, renderer);
renderText(text3DModels, textX3DModels, textY3DModels- scrollOffsetY, white, NunitoFont, renderer);
renderText(textEbooks, textXEbooks, textYEbooks- scrollOffsetY, white, NunitoFont, renderer);

SDL_DestroyTexture(SearchIconTexture);
SDL_DestroyTexture(BellIconTexture);

// Quit SDL_image (somewhere in your cleanup code)
IMG_Quit();
}
    void cleanup() override {
        NavigationMenu::cleanup();
    }
};



class Verification :public State  {
protected:

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

    Verification(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* NunitoFont)
    : State(window, renderer, NunitoFont),
      
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
         
        } else if (enteringverificationCode) {
           
            verificationCode += event.text.text;
           
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
       else if (event.key.keysym.sym == SDLK_DOWN) {
        if (enteringEmail) {
            enteringEmail = false;
            enteringverificationCode = true;
        }
    } else if (event.key.keysym.sym == SDLK_UP) {
        if (enteringverificationCode) {
            enteringverificationCode = false;
            enteringEmail = true;
        }
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

            if (isEmailInput) {
        GVCode =  sendVerificationCodeToEmail(emailAddress);
    } else {
        GVCode =  sendVerificationCodeToPhone(phoneNumber);
    }
        }


        // Resend Code Link
        if (mouseX >= textX7 && mouseX <= textX7 + textWidth7&& mouseY >= textY7 && mouseY <= textHeight7) {

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
TTF_SizeText(NunitoFont, text1, &textWidth1, &textHeight1);
TTF_SizeText(NunitoFont, text2a, &textWidth2a, &textHeight2a);
TTF_SizeText(NunitoFont, text2b, &textWidth2b, &textHeight2b);
TTF_SizeText(NunitoFont, text3.c_str(), &textWidth3, &textHeight3);
TTF_SizeText(NunitoFont, text4, &textWidth4, &textHeight4);
TTF_SizeText(NunitoFont, text5.c_str(), &textWidth5, &textHeight5);
TTF_SizeText(NunitoFont, text6, &textWidth6, &textHeight6);
TTF_SizeText(NunitoFont, text7, &textWidth7, &textHeight7);
 TTF_SizeText(NunitoFont, text8, &textWidth8, &textHeight8);

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
boxX = 53;



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
    renderText(text1, textX1, textY1, white, NunitoFont, renderer);
    renderText(text2a, textX2a, textY2a, grey, NunitoFont, renderer);
    renderText(text2b, textX2b, textY2b, grey, NunitoFont, renderer);
    renderText(text4, textX4, textY4, white, NunitoFont, renderer); 
    renderText(text6, textX6, textY6, white, NunitoFont, renderer); 
    renderText(text7, textX7, textY7, white, NunitoFont, renderer); 
    renderText(text8, textX8, textY8, black, NunitoFont, renderer); 
// Only render the relevant message based on the flags
    if (renderExpireMessage) {
        if (TTF_SizeText(NunitoFont, VerificationExpireMessage.c_str(), &textWidthVerificationMessage, &textHeightVerificationMessage) == 0) {
            textXVerificationMessage = boxX + (boxWidth - textWidthVerificationMessage) / 2;
            renderText(VerificationExpireMessage, textXVerificationMessage, textYVerificationMessage, VerificationMessageColor, NunitoFont, renderer);
        }
    } else if (renderIncorrectMessage) {
        if (TTF_SizeText(NunitoFont, VerificationIncorrectMessage.c_str(), &textWidthVerificationMessage, &textHeightVerificationMessage) == 0) {
            textXVerificationMessage = boxX + (boxWidth - textWidthVerificationMessage) / 2;
            renderText(VerificationIncorrectMessage, textXVerificationMessage, textYVerificationMessage, VerificationMessageColor, NunitoFont, renderer);
        }
    } else if (renderSuccessMessage) {
        if (TTF_SizeText(NunitoFont, VerificationSuccessMessage.c_str(), &textWidthVerificationMessage, &textHeightVerificationMessage) == 0) {
            textXVerificationMessage = boxX + (boxWidth - textWidthVerificationMessage) / 2;
            renderText(VerificationSuccessMessage, textXVerificationMessage, textYVerificationMessage, VerificationMessageColor, NunitoFont, renderer);
        }
    }




// Render email/phone input

// Check if the user input is an email
if (     enteringEmail &&      !userInput.empty()) {
    if (isEmail(userInput)) {
        emailAddress = userInput;
        isEmailInput = true;
        renderText( emailAddress.c_str(), EmailBoxX, EmailBoxY, black, NunitoFont, renderer);
    } else {
        phoneNumber = userInput;
        isEmailInput = false;
        renderText( phoneNumber.c_str(), EmailBoxX, EmailBoxY, black, NunitoFont, renderer);
    }
} else {

if (userInput.empty()) {
        renderText("Enter Email Address or Phone", textX3, textY3, grey, NunitoFont, renderer);
    } else {
        if (isEmail(userInput)) {
        emailAddress = userInput;
        isEmailInput = true;
        renderText( emailAddress.c_str(), EmailBoxX, EmailBoxY, black, NunitoFont, renderer);
    } else {
        phoneNumber = userInput;
        isEmailInput = false;
        renderText( phoneNumber.c_str(), EmailBoxX, EmailBoxY, black, NunitoFont, renderer);
    }
    }  
}
   // RenderverificationCode
  if (enteringverificationCode && !verificationCode.empty()) {
        renderText(verificationCode.c_str(), verificationCodeBoxX, verificationCodeBoxY, black, NunitoFont, renderer);
    } else {
         if (verificationCode.empty()) {
         renderText("Enter Verification Code", textX5, textY5, grey, NunitoFont, renderer);
    } else {
        renderText(verificationCode.c_str(), verificationCodeBoxX, verificationCodeBoxY, black, NunitoFont, renderer);
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
 FVerificationScreenState (SDL_Window* window, SDL_Renderer* renderer, TTF_Font* NunitoFont)
    : Verification (window ,renderer, NunitoFont ) 
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
SVerificationScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* NunitoFont)
    : Verification (window ,renderer, NunitoFont )  
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
   PasswordResetScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* NunitoFont)
        : State(window, renderer, NunitoFont), newPassword(""),confirmPassword(""), enteringNewPassword(true), enteringconfirmPassword(false) {
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
   HelpScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* NunitoFont)
        : State(window, renderer, NunitoFont){
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






















class ProfileScreenState : public State {
private:
     SDL_Color white = { 255, 255, 255, 255 };
    SDL_Color grey = { 100, 100, 100, 255 };
    SDL_Color black = { 0, 0, 0, 255 };
    SDL_Color darkgreen = { 0, 50, 0, 255  }; 
    SDL_Color maroon = { 128, 0, 0, 255 };
 
//OK SO THIS IS MY NEW TARGET

//COME ON AYESHA MAKE IT HAPPEN 

public:
   ProfileScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* NunitoFont)
        : State(window, renderer, NunitoFont){
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
class ProfileUpdateScreenState : public NavigationMenu{
private:
sqlite3* db; 
    User* currentUser; // Pointer to the current user


    SDL_Color white = { 255, 255, 255, 255 };
    SDL_Color grey = { 100, 100, 100, 255 };
    SDL_Color black = { 0, 0, 0, 255 };
    SDL_Color darkgreen = { 0, 50, 0, 255 };
    SDL_Color maroon = { 128, 0, 0, 255 };
    SDL_Color skyblue = {135, 206, 235, 255};

    // Input Variables
    std::string name, age, gender, bio, field_of_interest, date_of_birth, spoken_languages, hobbies;
    std::string linkedin, twitter, facebook, instagram;
    std::string email, phone_number;
    std::string highest_degree, major_field;
    std::string health_conditions, fitness_routine, major_illnesses, mental_health_status, sleep_patterns;
    std::string neuropsychological_assessments, eeg, qeeg, fmri, mri, ct_scan, evoked_potentials, sleep_studies, csf_analysis;
    std::string text_content, pdfs, images, videos, audio, spreadsheets, presentations, code, models, ebooks;
    std::string primary_contact_name, relationship, emergency_phone_number;
    std::string consent_forms, license_agreements, terms_of_service;

    // Flags for entering text
    bool enteringName = false, enteringAge = false, enteringGender = false, enteringBio = false, enteringFieldOfInterest = false;
    bool enteringDateOfBirth = false, enteringSpokenLanguages = false, enteringHobbies = false;
    bool enteringLinkedin = false, enteringTwitter = false, enteringFacebook = false, enteringInstagram = false;
    bool enteringEmail = false, enteringPhoneNumber = false;
    bool enteringHighestDegree = false, enteringMajorField = false;
    bool enteringHealthConditions = false, enteringFitnessRoutine = false, enteringMajorIllnesses = false;
    bool enteringMentalHealthStatus = false, enteringSleepPatterns = false;

    bool enteringNeuropsychologicalAssessments = false, enteringEEG = false, enteringQEEG = false, enteringFMRI = false;
    bool enteringMRI = false, enteringCTScan = false, enteringEvokedPotentials = false, enteringSleepStudies = false, enteringCSFAnalysis = false;
    bool enteringTextContent = false, enteringPdfs = false, enteringImages = false, enteringVideos = false;
    bool enteringAudio = false, enteringSpreadsheets = false, enteringPresentations = false, enteringCode = false;
    bool enteringModels = false, enteringEbooks = false;

    bool enteringPrimaryContactName = false, enteringRelationship = false, enteringEmergencyPhoneNumber = false;

bool showPersonalInfoDetails = false;
bool showSocialMediaDetails = false;
bool showContactInfoDetails = false;
bool showEducationInfoDetails = false;
bool showHealthWellnessDetails = false;
bool showCognitiveReportsDetails = false;
bool showCustomContentDetails = false;
bool showEmergencyContactDetails = false;
bool showLegalConsentDetails = false;




bool showpersonalInfoText=true;
bool showsocialMediaText=true;
bool showcontactInfoText=true;
bool showeducationInfoText=true;
bool showhealthWellnessText=true;
bool showcognitiveReportsText=true;
bool showcustomContentText=true;
bool showemergencyContactText=true;
bool showlegalConsentText=true;



bool showsocialMediaText2=false;
bool showcontactInfoText3=false;
bool showeducationInfoText4=false;
bool showhealthWellnessText5=false;
bool showcognitiveReportsText6=false;
bool showcustomContentText7=false;
bool showemergencyContactText8=false;
bool showlegalConsentText9=false;






    const int box_X = 330;
    const int box_X2 = 380;

    // Assign the same X position to all boxes
    const int nameBox_X = box_X;
    const int ageBox_X = box_X;
    const int genderBox_X = box_X;
    const int bioBox_X = box_X;
    const int fieldOfInterestBox_X = box_X;
    const int dateOfBirthBox_X = box_X;
    const int spokenLanguagesBox_X = box_X;
    const int hobbiesBox_X = box_X;

    const int linkedinBox_X = box_X;
    const int twitterBox_X = box_X;
    const int facebookBox_X = box_X;
    const int instagramBox_X = box_X;

    const int emailBox_X = box_X;
    const int phoneNumberBox_X = box_X;

    const int highestDegreeBox_X = box_X;
    const int majorFieldBox_X = box_X;

    const int healthConditionsBox_X = box_X;
    const int fitnessRoutineBox_X = box_X;
    const int majorIllnessesBox_X = box_X;
    const int mentalHealthStatusBox_X = box_X;
    const int sleepPatternsBox_X = box_X;

    const int neuropsychologicalAssessmentsBox_X = 100;
    const int eegBox_X = 100;
    const int qeegBox_X = 100;
    const int fmriBox_X = 100;
    const int mriBox_X = 100;
    const int ctScanBox_X = 100;
    const int evokedPotentialsBox_X = 100;
    const int sleepStudiesBox_X = 100;
    const int csfAnalysisBox_X = 100;

    const int textContentBox_X = box_X - 75;
    const int pdfsBox_X = box_X - 75;
    const int imagesBox_X = box_X - 75;
    const int videosBox_X = box_X - 75;
    const int audioBox_X = box_X - 75;
    const int spreadsheetsBox_X = box_X - 75;
    const int presentationsBox_X = box_X - 75;
    const int codeBox_X = box_X - 75;
    const int modelsBox_X = box_X - 75;
    const int ebooksBox_X = box_X - 75;

    const int primaryContactNameBox_X = box_X;
    const int relationshipBox_X = box_X;
    const int emergencyPhoneNumberBox_X = box_X;

    const int consentFormsBox_X = box_X - 50;
    const int licenseAgreementsBox_X = box_X - 50;
    const int termsOfServiceBox_X = box_X - 50;

    // Base Y position and gap
    const int baseY = 200;
    const int gap = 50;
    
    // Calculate Y positions based on baseY and gap
    // DefinING the circle's position and radius
   
    int centerY = (baseY -135)- scrollOffsetY; 

    int circleradius = 80;   // radius of the circle








//original ones
const int  yProfilePhoto = (baseY -40)- scrollOffsetY;

const int  yPersonalInfo = (baseY)- scrollOffsetY;

const int  ySocialMedia = (baseY +  gap)- scrollOffsetY;

const int  yContactInfo = ( baseY + 2 * gap)- scrollOffsetY;

const int  yEducationInfo = ( baseY + 3* gap)- scrollOffsetY;
const int  yHealthWellness = (baseY + 4* gap)- scrollOffsetY;
const int  yCognitiveReports = ( baseY +5* gap)- scrollOffsetY;
const int  yCustomContent = ( baseY + 6 * gap)- scrollOffsetY;
const int  yEmergencyContact = (baseY + 7 * gap)- scrollOffsetY;
const int  yLegalConsent = (baseY + 8 * gap)- scrollOffsetY;




//for peronal info

//const int  yPersonalInfo = (baseY)- scrollOffsetY;
const int nameBox_Y =( baseY+gap)- scrollOffsetY;
const int ageBox_Y =( baseY + 2*gap)- scrollOffsetY;
const int genderBox_Y =( baseY + 3 * gap)- scrollOffsetY;
const int bioBox_Y = (baseY + 4 * gap)- scrollOffsetY;
const int fieldOfInterestBox_Y =( baseY + 5 * gap)- scrollOffsetY;
const int dateOfBirthBox_Y =( baseY + 6 * gap)- scrollOffsetY;
const int spokenLanguagesBox_Y =( baseY + 7 * gap)- scrollOffsetY;
const int hobbiesBox_Y = (baseY + 8 * gap)- scrollOffsetY;
const int ySocialMedia1= ( baseY + 9 * gap)- scrollOffsetY;

const int yContactInfo1= ( baseY + 10 * gap)- scrollOffsetY;

const int yEducationInfo1= ( baseY + 11* gap)- scrollOffsetY;

const int yHealthWellness1= ( baseY + 12 * gap)- scrollOffsetY;

const int yCognitiveReports1= ( baseY + 13 * gap)- scrollOffsetY;
const int yCustomContent1= ( baseY + 14 * gap)- scrollOffsetY;

const int yEmergencyContact1= ( baseY + 15 * gap)- scrollOffsetY;

const int yLegalConsent1= ( baseY + 16 * gap)- scrollOffsetY;



//for socail media
const int  yPersonalInfo2 = (baseY)- scrollOffsetY;


const int  ySocialMedia2 = (baseY +gap)- scrollOffsetY;

const int linkedinBox_Y = (baseY +  2* gap)- scrollOffsetY;
const int twitterBox_Y =( baseY + 3* gap)- scrollOffsetY;
const int facebookBox_Y = (baseY + 4 * gap)- scrollOffsetY;
const int instagramBox_Y = (baseY + 5 * gap)- scrollOffsetY;
const int yContactInfo2= ( baseY + 6 * gap)- scrollOffsetY;

const int yEducationInfo2= ( baseY + 7* gap)- scrollOffsetY;

const int yHealthWellness2= ( baseY + 8* gap)- scrollOffsetY;

const int yCognitiveReports2= ( baseY + 9* gap)- scrollOffsetY;
const int yCustomContent2= ( baseY + 10 * gap)- scrollOffsetY;

const int yEmergencyContact2= ( baseY + 11* gap)- scrollOffsetY;

const int yLegalConsent2= ( baseY + 12 * gap)- scrollOffsetY;








//for contact
const int  yPersonalInfo3 = (baseY)- scrollOffsetY;
const int ySocialMedia3= ( baseY + gap)- scrollOffsetY;



const int  yContactInfo3 = ( baseY +2*gap)- scrollOffsetY;
const int emailBox_Y =( baseY + 3*  gap)- scrollOffsetY;
const int phoneNumberBox_Y =( baseY + 4 * gap)- scrollOffsetY;

const int yEducationInfo3= ( baseY + 5* gap)- scrollOffsetY;

const int yHealthWellness3= ( baseY + 6 * gap)- scrollOffsetY;

const int yCognitiveReports3= ( baseY + 7 * gap)- scrollOffsetY;
const int yCustomContent3= ( baseY + 8 * gap)- scrollOffsetY;

const int yEmergencyContact3= ( baseY + 9 * gap)- scrollOffsetY;

const int yLegalConsent3= ( baseY + 10 * gap)- scrollOffsetY;





//for education 
const int  yPersonalInfo4 = (baseY)- scrollOffsetY;
const int ySocialMedia4= ( baseY +  gap)- scrollOffsetY;

const int yContactInfo4= ( baseY + 2 * gap)- scrollOffsetY;

const int  yEducationInfo4 = ( baseY+3*gap )- scrollOffsetY;
const int highestDegreeBox_Y =( baseY + 4*  gap)- scrollOffsetY;
const int majorFieldBox_Y =( baseY + 5 * gap)- scrollOffsetY;

const int yHealthWellness4= ( baseY + 6 * gap)- scrollOffsetY;

const int yCognitiveReports4= ( baseY + 7* gap)- scrollOffsetY;
const int yCustomContent4= ( baseY + 8 * gap)- scrollOffsetY;

const int yEmergencyContact4= ( baseY + 9 * gap)- scrollOffsetY;

const int yLegalConsent4= ( baseY + 10 * gap)- scrollOffsetY;








//for healthwellness
const int  yPersonalInfo5 = (baseY)- scrollOffsetY;
const int ySocialMedia5= ( baseY + gap)- scrollOffsetY;

const int yContactInfo5= ( baseY + 2 * gap)- scrollOffsetY;

const int yEducationInfo5= ( baseY + 3* gap)- scrollOffsetY;
const int  yHealthWellness5 = (baseY+4 *gap  )- scrollOffsetY;
const int healthConditionsBox_Y = (baseY + 5*  gap)- scrollOffsetY;
const int fitnessRoutineBox_Y =( baseY + 6 * gap)- scrollOffsetY;
const int majorIllnessesBox_Y = (baseY + 7 * gap)- scrollOffsetY;
const int mentalHealthStatusBox_Y =( baseY +8 * gap)- scrollOffsetY;
const int sleepPatternsBox_Y =( baseY +9 * gap)- scrollOffsetY;
const int yCognitiveReports5= ( baseY + 10 * gap)- scrollOffsetY;
const int yCustomContent5= ( baseY + 11 * gap)- scrollOffsetY;

const int yEmergencyContact5= ( baseY + 12 * gap)- scrollOffsetY;

const int yLegalConsent5= ( baseY + 13 * gap)- scrollOffsetY;









//for cognitive
const int  yPersonalInfo6 = (baseY)- scrollOffsetY;
const int ySocialMedia6= ( baseY +  gap)- scrollOffsetY;

const int yContactInfo6= ( baseY + 2 * gap)- scrollOffsetY;

const int yEducationInfo6= ( baseY + 3* gap)- scrollOffsetY;

const int yHealthWellness6= ( baseY + 4 * gap)- scrollOffsetY;



const int  yCognitiveReports6 = ( baseY+5 * gap )- scrollOffsetY;
const int neuropsychologicalAssessmentsBox_Y =( baseY + 6* gap)- scrollOffsetY;
const int eegBox_Y =( baseY + 7 * gap)- scrollOffsetY;
const int qeegBox_Y =( baseY + 8 * gap)- scrollOffsetY;
const int fmriBox_Y = (baseY + 9 * gap)- scrollOffsetY;
const int mriBox_Y =( baseY + 10 * gap)- scrollOffsetY;
const int ctScanBox_Y =( baseY + 11 * gap)- scrollOffsetY;
const int evokedPotentialsBox_Y = (baseY + 12 * gap)- scrollOffsetY;
const int sleepStudiesBox_Y =( baseY +13 * gap)- scrollOffsetY;
const int csfAnalysisBox_Y = (baseY + 14 * gap)- scrollOffsetY;
const int yCustomContent6= ( baseY + 15 * gap)- scrollOffsetY;

const int yEmergencyContact6= ( baseY + 16 * gap)- scrollOffsetY;

const int yLegalConsent6= ( baseY + 17 * gap)- scrollOffsetY;









//for custom content
const int  yPersonalInfo7 = (baseY)- scrollOffsetY;
const int ySocialMedia7= ( baseY + gap)- scrollOffsetY;

const int yContactInfo7= ( baseY + 2 * gap)- scrollOffsetY;

const int yEducationInfo7= ( baseY + 3* gap)- scrollOffsetY;

const int yHealthWellness7= ( baseY + 4* gap)- scrollOffsetY;

const int yCognitiveReports7= ( baseY + 5 * gap)- scrollOffsetY;




const int  yCustomContent7 = ( baseY +6* gap)- scrollOffsetY;
const int textContentBox_Y =( baseY +7* gap)- scrollOffsetY;
const int pdfsBox_Y = (baseY + 8 * gap)- scrollOffsetY;
const int imagesBox_Y =( baseY + 9* gap)- scrollOffsetY;
const int videosBox_Y = (baseY + 10* gap)- scrollOffsetY;
const int audioBox_Y = (baseY + 11* gap)- scrollOffsetY;
const int spreadsheetsBox_Y =( baseY + 12* gap)- scrollOffsetY;
const int presentationsBox_Y =( baseY + 13 * gap)- scrollOffsetY;
const int codeBox_Y = (baseY +13 * gap)- scrollOffsetY;
const int modelsBox_Y = (baseY + 14 * gap)- scrollOffsetY;
const int ebooksBox_Y = (baseY + 15 * gap)- scrollOffsetY;
const int yEmergencyContact7= ( baseY + 16 * gap)- scrollOffsetY;

const int yLegalConsent7= ( baseY + 17 * gap)- scrollOffsetY;







//for emergency contact 
const int  yPersonalInfo8 = (baseY)- scrollOffsetY;
const int ySocialMedia8= ( baseY +  gap)- scrollOffsetY;

const int yContactInfo8= ( baseY + 2 * gap)- scrollOffsetY;

const int yEducationInfo8= ( baseY + 3* gap)- scrollOffsetY;

const int yHealthWellness8= ( baseY +4* gap)- scrollOffsetY;

const int yCognitiveReports8= ( baseY + 5* gap)- scrollOffsetY;
const int yCustomContent8= ( baseY + 6 * gap)- scrollOffsetY;




const int  yEmergencyContact8 = (baseY +7 *gap)- scrollOffsetY;
const int primaryContactNameBox_Y = (baseY +8* gap)- scrollOffsetY;
const int relationshipBox_Y = (baseY + 9 * gap)- scrollOffsetY;
const int emergencyPhoneNumberBox_Y = (baseY + 10* gap)- scrollOffsetY;

const int yLegalConsent8= ( baseY + 11 * gap)- scrollOffsetY;









//for legal consent
const int  yPersonalInfo9 = (baseY)- scrollOffsetY;
const int ySocialMedia9= ( baseY +  gap)- scrollOffsetY;

const int yContactInfo9= ( baseY + 2* gap)- scrollOffsetY;

const int yEducationInfo9= ( baseY + 3* gap)- scrollOffsetY;

const int yHealthWellness9= ( baseY +4 * gap)- scrollOffsetY;

const int yCognitiveReports9= ( baseY +5 * gap)- scrollOffsetY;
const int yCustomContent9= ( baseY +6 * gap)- scrollOffsetY;

const int yEmergencyContact9= ( baseY + 7 * gap)- scrollOffsetY;


const int  yLegalConsent9 = (baseY +8 * gap)- scrollOffsetY;
const int consentFormsBox_Y = (baseY +9* gap)- scrollOffsetY;
const int licenseAgreementsBox_Y = (baseY + 10* gap)- scrollOffsetY;
const int termsOfServiceBox_Y =( baseY + 11 * gap)- scrollOffsetY;




// Declarations for Widths
const int uploadboxwidth = 100;
const int checkboxwidth = 20;
const int nameBox_WIDTH = 300;
const int ageBox_WIDTH = 300;
const int genderBox_WIDTH = 300;
const int bioBox_WIDTH = 300;
const int fieldOfInterestBox_WIDTH = 300;
const int dateOfBirthBox_WIDTH = 300;
const int spokenLanguagesBox_WIDTH = 300;
const int hobbiesBox_WIDTH = 300;

const int linkedinBox_WIDTH = 300;
const int twitterBox_WIDTH = 300;
const int facebookBox_WIDTH = 300;
const int instagramBox_WIDTH = 300;

const int emailBox_WIDTH = 300;
const int phoneNumberBox_WIDTH = 300;

const int highestDegreeBox_WIDTH = 300;
const int majorFieldBox_WIDTH = 300;

const int healthConditionsBox_WIDTH = 300;
const int fitnessRoutineBox_WIDTH = 300;
const int majorIllnessesBox_WIDTH = 300;
const int mentalHealthStatusBox_WIDTH = 300;
const int sleepPatternsBox_WIDTH = 300;



const int primaryContactNameBox_WIDTH = 300;
const int relationshipBox_WIDTH = 300;
const int emergencyPhoneNumberBox_WIDTH = 300;




// Declarations for Heights
const int inputBoxHeight = 30; // Same height for all fields
const int  uploadboxheight=30;
const int checkboxheight = 20;
// Radius for rounded corners
const int radius = 5;
// Width and Height Variables for Text 
int textWidthProfilePhoto, textHeightProfilePhoto;
int textWidthPersonalInfo, textHeightPersonalInfo;
int textWidthSocialMedia, textHeightSocialMedia;
int textWidthContactInfo, textHeightContactInfo;
int textWidthEducationInfo, textHeightEducationInfo;
int textWidthHealthWellness, textHeightHealthWellness;
int textWidthCognitiveReports, textHeightCognitiveReports;
int textWidthCustomContent, textHeightCustomContent;
int textWidthEmergencyContact, textHeightEmergencyContact;
int textWidthLegalConsent, textHeightLegalConsent;

// Width and Height Variables for Display Text Variables
int textWidthName, textHeightName;
int textWidthAge, textHeightAge;
int textWidthGender, textHeightGender;
int textWidthBio, textHeightBio;
int textWidthFieldOfInterest, textHeightFieldOfInterest;
int textWidthDateOfBirth, textHeightDateOfBirth;
int textWidthSpokenLanguages, textHeightSpokenLanguages;
int textWidthHobbies, textHeightHobbies;

int textWidthLinkedin, textHeightLinkedin;
int textWidthTwitter, textHeightTwitter;
int textWidthFacebook, textHeightFacebook;
int textWidthInstagram, textHeightInstagram;

int textWidthEmail, textHeightEmail;
int textWidthPhoneNumber, textHeightPhoneNumber;

int textWidthHighestDegree, textHeightHighestDegree;
int textWidthMajorField, textHeightMajorField;

int textWidthHealthConditions, textHeightHealthConditions;
int textWidthFitnessRoutine, textHeightFitnessRoutine;
int textWidthMajorIllnesses, textHeightMajorIllnesses;
int textWidthMentalHealthStatus, textHeightMentalHealthStatus;
int textWidthSleepPatterns, textHeightSleepPatterns;

int textWidthNeuropsychologicalAssessments, textHeightNeuropsychologicalAssessments;
int textWidthEeg, textHeightEeg;
int textWidthQeeg, textHeightQeeg;
int textWidthFmri, textHeightFmri;
int textWidthMri, textHeightMri;
int textWidthCtScan, textHeightCtScan;
int textWidthEvokedPotentials, textHeightEvokedPotentials;
int textWidthSleepStudies, textHeightSleepStudies;
int textWidthCsfAnalysis, textHeightCsfAnalysis;

int textWidthTextContent, textHeightTextContent;
int textWidthPdfs, textHeightPdfs;
int textWidthImages, textHeightImages;
int textWidthVideos, textHeightVideos;
int textWidthAudio, textHeightAudio;
int textWidthSpreadsheets, textHeightSpreadsheets;
int textWidthPresentations, textHeightPresentations;
int textWidthCode, textHeightCode;
int textWidthModels, textHeightModels;
int textWidthEbooks, textHeightEbooks;

int textWidthPrimaryContactName, textHeightPrimaryContactName;
int textWidthRelationship, textHeightRelationship;
int textWidthEmergencyPhoneNumber, textHeightEmergencyPhoneNumber;

int textWidthConsentForms, textHeightConsentForms;
int textWidthLicenseAgreements, textHeightLicenseAgreements;
int textWidthTermsOfService, textHeightTermsOfService;
int centerX = (boxX + (boxWidth - (circleradius*2)) / 2)+68;

// X and Y Position Variables for Text Rendering
int xProfilePhoto = boxX + (boxWidth - textWidthProfilePhoto) / 2;

int xPersonalInfo =100;
int xSocialMedia = 100;
int xContactInfo = 100;
int xEducationInfo = 100;
int xHealthWellness = 100;
int xCognitiveReports = 100;
int xCustomContent =100;
int xEmergencyContact = 100;
int xLegalConsent = 100;


// X and Y Position Variables for Display Text Variables
int xName = 100;
int yName = nameBox_Y- scrollOffsetY;

int xAge = 100;
int yAge = ageBox_Y- scrollOffsetY;

int xGender = 100;
int yGender = genderBox_Y- scrollOffsetY;

int xBio = 100;
int yBio = bioBox_Y- scrollOffsetY;

int xFieldOfInterest =100;
int yFieldOfInterest = fieldOfInterestBox_Y- scrollOffsetY;

int xDateOfBirth = 100;
int yDateOfBirth = dateOfBirthBox_Y- scrollOffsetY;

int xSpokenLanguages =100;
int ySpokenLanguages = spokenLanguagesBox_Y- scrollOffsetY;

int xHobbies = 100;
int yHobbies = hobbiesBox_Y- scrollOffsetY;

int xLinkedin = 100;
int yLinkedin = linkedinBox_Y- scrollOffsetY;

int xTwitter = 100;
int yTwitter = twitterBox_Y- scrollOffsetY;

int xFacebook = 100;
int yFacebook = facebookBox_Y- scrollOffsetY;

int xInstagram = 100;
int yInstagram = instagramBox_Y- scrollOffsetY;

int xEmail = 100;
int yEmail = emailBox_Y- scrollOffsetY;

int xPhoneNumber = 100;
int yPhoneNumber = phoneNumberBox_Y- scrollOffsetY;

int xHighestDegree = 100;
int yHighestDegree = highestDegreeBox_Y- scrollOffsetY;

int xMajorField = 100;
int yMajorField = majorFieldBox_Y- scrollOffsetY;

int xHealthConditions = 100;
int yHealthConditions = healthConditionsBox_Y- scrollOffsetY;

int xFitnessRoutine = 100;
int yFitnessRoutine = fitnessRoutineBox_Y- scrollOffsetY;

int xMajorIllnesses = 100;
int yMajorIllnesses = majorIllnessesBox_Y- scrollOffsetY;

int xMentalHealthStatus = 100;
int yMentalHealthStatus = mentalHealthStatusBox_Y- scrollOffsetY;

int xSleepPatterns = 100;
int ySleepPatterns = sleepPatternsBox_Y- scrollOffsetY;



int xNeuropsychologicalAssessments = 100;
int yNeuropsychologicalAssessments = neuropsychologicalAssessmentsBox_Y -26- scrollOffsetY;

int xEeg = 100;
int yEeg = eegBox_Y-26- scrollOffsetY;

int xQeeg = 100;
int yQeeg = qeegBox_Y-26- scrollOffsetY;

int xFmri = 100;
int yFmri = fmriBox_Y-26- scrollOffsetY;

int xMri = 100;
int yMri = mriBox_Y-26- scrollOffsetY;

int xCtScan = 100;
int yCtScan = ctScanBox_Y-26- scrollOffsetY;

int xEvokedPotentials = 100;
int yEvokedPotentials = evokedPotentialsBox_Y-26- scrollOffsetY;

int xSleepStudies = 100;
int ySleepStudies = sleepStudiesBox_Y-26- scrollOffsetY;

int xCsfAnalysis = 100;
int yCsfAnalysis = csfAnalysisBox_Y-26- scrollOffsetY;





int xTextContent = 100;
int yTextContent = textContentBox_Y- scrollOffsetY;

int xPdfs = 100;
int yPdfs = pdfsBox_Y- scrollOffsetY;

int xImages = 100;
int yImages = imagesBox_Y- scrollOffsetY;

int xVideos = 100;
int yVideos = videosBox_Y- scrollOffsetY;

int xAudio = 100;
int yAudio = audioBox_Y- scrollOffsetY;

int xSpreadsheets = 100;
int ySpreadsheets = spreadsheetsBox_Y- scrollOffsetY;

int xPresentations = 100;
int yPresentations = presentationsBox_Y- scrollOffsetY;

int xCode = 100;
int yCode = codeBox_Y- scrollOffsetY;

int xModels = 100;
int yModels = modelsBox_Y- scrollOffsetY;

int xEbooks = 100;
int yEbooks = ebooksBox_Y- scrollOffsetY;

int xPrimaryContactName =100;
int yPrimaryContactName = primaryContactNameBox_Y- scrollOffsetY;

int xRelationship = 100;
int yRelationship = relationshipBox_Y- scrollOffsetY;

int xEmergencyPhoneNumber =100;
int yEmergencyPhoneNumber = emergencyPhoneNumberBox_Y- scrollOffsetY;

int xConsentForms = 100;
int yConsentForms = consentFormsBox_Y- scrollOffsetY;

int xLicenseAgreements = 100;
int yLicenseAgreements = licenseAgreementsBox_Y- scrollOffsetY;

int xTermsOfService = 100;
int yTermsOfService = termsOfServiceBox_Y- scrollOffsetY;

SDL_Rect checkbox1;
SDL_Rect checkbox2;
SDL_Rect checkbox3;

bool isCheckbox1Checked = false;
bool isCheckbox2Checked = false;
bool isCheckbox3Checked = false;
int checkboxSize2 = 20;


// Coordinates for the tick mark
int tickStartY1 = (consentFormsBox_Y - scrollOffsetY) + checkboxSize2 / 2 + checkboxSize2 / 4; // Bottom left Y
int tickMiddleY1 = (consentFormsBox_Y - scrollOffsetY) + checkboxSize2 - checkboxSize2 / 4;     // Middle Y
int tickEndY1 = (consentFormsBox_Y - scrollOffsetY) + checkboxSize2 / 4;                       // Top right Y

int tickStartX1 = consentFormsBox_X + checkboxSize2 / 4;                                       // Bottom left X
int tickMiddleX1 = consentFormsBox_X + checkboxSize2 / 2;                                      // Middle X
int tickEndX1 = consentFormsBox_X + checkboxSize2 - checkboxSize2 / 4;                         // Top right X




int tickStartY2 = (licenseAgreementsBox_Y- scrollOffsetY) + checkboxSize2 / 2+ checkboxSize2 / 4;
    int  tickMiddleY2 = (licenseAgreementsBox_Y- scrollOffsetY) + checkboxSize2 - checkboxSize2 / 4;
    int  tickEndY2 = (licenseAgreementsBox_Y- scrollOffsetY )+ checkboxSize2 / 4;


int  tickStartX2= licenseAgreementsBox_X+ checkboxSize2 / 4;
int tickMiddleX2=licenseAgreementsBox_X + checkboxSize2 / 2;
 int tickEndX2 = licenseAgreementsBox_X + checkboxSize2 - checkboxSize2 / 4;


 
int tickStartY3 = (termsOfServiceBox_Y- scrollOffsetY)+ checkboxSize2 / 2+ checkboxSize2 / 4;
    int  tickMiddleY3 = (termsOfServiceBox_Y- scrollOffsetY) + checkboxSize2 - checkboxSize2 / 4;
    int  tickEndY3 = (termsOfServiceBox_Y- scrollOffsetY) + checkboxSize2 / 4;


int  tickStartX3 = termsOfServiceBox_X + checkboxSize2 / 4;
int tickMiddleX3 =termsOfServiceBox_X + checkboxSize2 / 2;
 int tickEndX3 =termsOfServiceBox_X + checkboxSize2 - checkboxSize2 / 4;


// Text Labels
const char* profilePhotoText = "Profile Photo";

const char* personalInfoText = "Personal Information";
const char* socialMediaText = "Social Media Profiles";
const char* contactInfoText = "Contact Information";
const char* educationInfoText = "Education Information";
const char* healthWellnessText = "Health and Wellness";
const char* cognitiveReportsText = "Cognitive Reports";
const char* customContentText = "Custom Content";
const char* emergencyContactText = "Emergency Contact Information";
const char* legalConsentText = "Legal and Consent";

 
public:
    // constructor
    ProfileUpdateScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* NunitoFont, TTF_Font* NimbusRomFont, User* user, sqlite3* db)
        : NavigationMenu(window, renderer, NunitoFont), currentUser(user), db(db) 

, name(""), age(""), gender(""), bio(""), field_of_interest(""), date_of_birth(""), spoken_languages(""), hobbies
    (""), linkedin(""), twitter(""), facebook(""), instagram
    (""), email(""), phone_number
    (""), highest_degree(""), major_field
    (""), health_conditions(""), fitness_routine(""), major_illnesses(""), mental_health_status(""), sleep_patterns
    
    (""), primary_contact_name(""), relationship(""), emergency_phone_number
    ("")


       , enteringName(true), enteringAge(false), enteringGender(false), enteringBio(false), enteringFieldOfInterest(false)
   , enteringDateOfBirth(false), enteringSpokenLanguages(false), enteringHobbies(false)
   , enteringLinkedin(false), enteringTwitter(false), enteringFacebook(false), enteringInstagram(false)
   , enteringEmail(false), enteringPhoneNumber(false)
   , enteringHighestDegree(false), enteringMajorField(false)
   , enteringHealthConditions(false), enteringFitnessRoutine(false), enteringMajorIllnesses(false)
   , enteringMentalHealthStatus(false), enteringSleepPatterns(false)

   , enteringPrimaryContactName(false), enteringRelationship(false), enteringEmergencyPhoneNumber(false),
 showPersonalInfoDetails(false),
 showSocialMediaDetails(false),
 showContactInfoDetails(false),
 showEducationInfoDetails(false),
 showHealthWellnessDetails(false),
 showCognitiveReportsDetails(false),
 showCustomContentDetails(false),
 showEmergencyContactDetails(false),
 showLegalConsentDetails(false),



showpersonalInfoText(true),
showsocialMediaText(true),
showcontactInfoText(true),
showeducationInfoText(true),
showhealthWellnessText(true),
showcognitiveReportsText(true),
showcustomContentText(true),
showemergencyContactText(true),
showlegalConsentText(true),


 showsocialMediaText2(false),showcontactInfoText3(false), showeducationInfoText4(false), showhealthWellnessText5(false),showcognitiveReportsText6(false), showcustomContentText7(false), showemergencyContactText8(false), showlegalConsentText9(false)

        
        
        
        
        
        
        
        
        
        
        
        
        
        {

             if (currentUser == nullptr) {
            std::cerr << "Warning: currentUser is nullptr." << std::endl;
        }
        if (db == nullptr) {
            std::cerr << "Warning: db is nullptr." << std::endl;

            std::cerr << "Database pointer value: " << db << std::endl;

        }
        SDL_StartTextInput();
        // Initialize other necessary variables if needed
        isCheckbox1Checked = false;
        isCheckbox2Checked = false;
        isCheckbox3Checked = false;
    }
 void saveUserAgreements() {
        // Ensure currentUser is not null
        if (currentUser) {
            std::string username = currentUser->getUsername();
            std::string emailAddress = currentUser->getEmailAddress();
            saveAgreementsToDatabase(db, *currentUser,isCheckbox1Checked, isCheckbox2Checked, isCheckbox3Checked);
        } else  if (currentUser == nullptr) {
            std::cerr << "Current user is not set." << std::endl;
            return;
        }
        if (db == nullptr) {
            std::cerr << "Database connection is not set." << std::endl;
            return;
        }
    }



    void handleEvents(SDL_Event& event) override {
         NavigationMenu::handleEvents(event);
  

    if (currentUser) {
        std::string username = currentUser->getUsername();
        std::string emailAddress = currentUser->getEmailAddress();
        saveAgreementsToDatabase(db, *currentUser, isCheckbox1Checked, isCheckbox2Checked, isCheckbox3Checked);
    } else {
        std::cerr << "Current user is not set." << std::endl;
    }

    if (event.type == SDL_TEXTINPUT) {
        if (enteringName) {
            name += event.text.text;
        } else if (enteringAge) {
            age += event.text.text;
        } else if (enteringGender) {
            gender += event.text.text;
        } else if (enteringBio) {
            bio += event.text.text;
        } else if (enteringFieldOfInterest) {
            field_of_interest += event.text.text;
        } else if (enteringDateOfBirth) {
            date_of_birth += event.text.text;
        } else if (enteringSpokenLanguages) {
            spoken_languages += event.text.text;
        } else if (enteringHobbies) {
            hobbies += event.text.text;
        } else if (enteringLinkedin) {
            linkedin += event.text.text;
        } else if (enteringTwitter) {
            twitter += event.text.text;
        } else if (enteringFacebook) {
            facebook += event.text.text;
        } else if (enteringInstagram) {
            instagram += event.text.text;
        } else if (enteringEmail) {
            email += event.text.text;
        } else if (enteringPhoneNumber) {
            phone_number += event.text.text;
        } else if (enteringHighestDegree) {
            highest_degree += event.text.text;
        } else if (enteringMajorField) {
            major_field += event.text.text;
        } else if (enteringHealthConditions) {
            health_conditions += event.text.text;
        } else if (enteringFitnessRoutine) {
            fitness_routine += event.text.text;
        } else if (enteringMajorIllnesses) {
            major_illnesses += event.text.text;
        } else if (enteringMentalHealthStatus) {
            mental_health_status += event.text.text;
        } else if (enteringSleepPatterns) {
            sleep_patterns += event.text.text;
        } else if (enteringPrimaryContactName) {
            primary_contact_name += event.text.text;
        } else if (enteringRelationship) {
            relationship += event.text.text;
        } else if (enteringEmergencyPhoneNumber) {
            emergency_phone_number += event.text.text;
        }
    }

    if (event.type == SDL_KEYDOWN) {
        switch (event.key.keysym.sym) {
            case SDLK_UP:
                // Navigate to the previous input field
                if (enteringEmergencyPhoneNumber) {
                    enteringPrimaryContactName = true;
                    enteringEmergencyPhoneNumber = false;
                } else if (enteringPrimaryContactName) {
                    enteringSleepPatterns = true;
                    enteringPrimaryContactName = false;
                } else if (enteringSleepPatterns) {
                    enteringMentalHealthStatus = true;
                    enteringSleepPatterns = false;
                } else if (enteringMentalHealthStatus) {
                    enteringMajorIllnesses = true;
                    enteringMentalHealthStatus = false;
                } else if (enteringMajorIllnesses) {
                    enteringFitnessRoutine = true;
                    enteringMajorIllnesses = false;
                } else if (enteringFitnessRoutine) {
                    enteringHealthConditions = true;
                    enteringFitnessRoutine = false;
                } else if (enteringHealthConditions) {
                    enteringHighestDegree = true;
                    enteringHealthConditions = false;
                } else if (enteringHighestDegree) {
                    enteringPhoneNumber = true;
                    enteringHighestDegree = false;
                } else if (enteringPhoneNumber) {
                    enteringEmail = true;
                    enteringPhoneNumber = false;
                } else if (enteringEmail) {
                    enteringInstagram = true;
                    enteringEmail = false;
                } else if (enteringInstagram) {
                    enteringFacebook = true;
                    enteringInstagram = false;
                } else if (enteringFacebook) {
                    enteringTwitter = true;
                    enteringFacebook = false;
                } else if (enteringTwitter) {
                    enteringLinkedin = true;
                    enteringTwitter = false;
                } else if (enteringLinkedin) {
                    enteringHobbies = true;
                    enteringLinkedin = false;
                } else if (enteringHobbies) {
                    enteringSpokenLanguages = true;
                    enteringHobbies = false;
                } else if (enteringSpokenLanguages) {
                    enteringDateOfBirth = true;
                    enteringSpokenLanguages = false;
                } else if (enteringDateOfBirth) {
                    enteringFieldOfInterest = true;
                    enteringDateOfBirth = false;
                } else if (enteringFieldOfInterest) {
                    enteringBio = true;
                    enteringFieldOfInterest = false;
                } else if (enteringBio) {
                    enteringGender = true;
                    enteringBio = false;
                } else if (enteringGender) {
                    enteringAge = true;
                    enteringGender = false;
                } else if (enteringAge) {
                    enteringName = true;
                    enteringAge = false;
                } else if (enteringName) {
                    enteringName = false; // or loop back to first field if needed
                }
                break;

            case SDLK_DOWN:
                // Navigate to the next input field
                if (enteringName) {
                    enteringAge = true;
                    enteringName = false;
                } else if (enteringAge) {
                    enteringGender = true;
                    enteringAge = false;
                } else if (enteringGender) {
                    enteringBio = true;
                    enteringGender = false;
                } else if (enteringBio) {
                    enteringFieldOfInterest = true;
                    enteringBio = false;
                } else if (enteringFieldOfInterest) {
                    enteringDateOfBirth = true;
                    enteringFieldOfInterest = false;
                } else if (enteringDateOfBirth) {
                    enteringSpokenLanguages = true;
                    enteringDateOfBirth = false;
                } else if (enteringSpokenLanguages) {
                    enteringHobbies = true;
                    enteringSpokenLanguages = false;
                } else if (enteringHobbies) {
                    enteringLinkedin = true;
                    enteringHobbies = false;
                } else if (enteringLinkedin) {
                    enteringTwitter = true;
                    enteringLinkedin = false;
                } else if (enteringTwitter) {
                    enteringFacebook = true;
                    enteringTwitter = false;
                } else if (enteringFacebook) {
                    enteringInstagram = true;
                    enteringFacebook = false;
                } else if (enteringInstagram) {
                    enteringEmail = true;
                    enteringInstagram = false;
                } else if (enteringEmail) {
                    enteringPhoneNumber = true;
                    enteringEmail = false;
                } else if (enteringPhoneNumber) {
                    enteringHighestDegree = true;
                    enteringPhoneNumber = false;
                } else if (enteringHighestDegree) {
                    enteringHealthConditions = true;
                    enteringHighestDegree = false;
                } else if (enteringHealthConditions) {
                    enteringFitnessRoutine = true;
                    enteringHealthConditions = false;
                } else if (enteringFitnessRoutine) {
                    enteringMajorIllnesses = true;
                    enteringFitnessRoutine = false;
                } else if (enteringMajorIllnesses) {
                    enteringMentalHealthStatus = true;
                    enteringMajorIllnesses = false;
                } else if (enteringMentalHealthStatus) {
                    enteringSleepPatterns = true;
                    enteringMentalHealthStatus = false;
                } else if (enteringSleepPatterns) {
                    enteringPrimaryContactName = true;
                    enteringSleepPatterns = false;
                } else if (enteringPrimaryContactName) {
                    enteringEmergencyPhoneNumber = true;
                    enteringPrimaryContactName = false;
                } else if (enteringEmergencyPhoneNumber) {
                    enteringEmergencyPhoneNumber = false; // or loop back to last field if needed
                }
                break;

            case SDLK_RETURN:
                // Confirm the current input or navigate to the next input field
                if (enteringName) {
                    enteringName = false;
                    enteringAge = true;
                } else if (enteringAge) {
                    enteringAge = false;
                    enteringGender = true;
                } else if (enteringGender) {
                    enteringGender = false;
                    enteringBio = true;
                } else if (enteringBio) {
                    enteringBio = false;
                    enteringFieldOfInterest = true;
                } else if (enteringFieldOfInterest) {
                    enteringFieldOfInterest = false;
                    enteringDateOfBirth = true;
                } else if (enteringDateOfBirth) {
                    enteringDateOfBirth = false;
                    enteringSpokenLanguages = true;
                } else if (enteringSpokenLanguages) {
                    enteringSpokenLanguages = false;
                    enteringHobbies = true;
                } else if (enteringHobbies) {
                    enteringHobbies = false;
                    enteringLinkedin = true;
                } else if (enteringLinkedin) {
                    enteringLinkedin = false;
                    enteringTwitter = true;
                } else if (enteringTwitter) {
                    enteringTwitter = false;
                    enteringFacebook = true;
                } else if (enteringFacebook) {
                    enteringFacebook = false;
                    enteringInstagram = true;
                } else if (enteringInstagram) {
                    enteringInstagram = false;
                    enteringEmail = true;
                } else if (enteringEmail) {
                    enteringEmail = false;
                    enteringPhoneNumber = true;
                } else if (enteringPhoneNumber) {
                    enteringPhoneNumber = false;
                    enteringHighestDegree = true;
                } else if (enteringHighestDegree) {
                    enteringHighestDegree = false;
                    enteringHealthConditions = true;
                } else if (enteringHealthConditions) {
                    enteringHealthConditions = false;
                    enteringFitnessRoutine = true;
                } else if (enteringFitnessRoutine) {
                    enteringFitnessRoutine = false;
                    enteringMajorIllnesses = true;
                } else if (enteringMajorIllnesses) {
                    enteringMajorIllnesses = false;
                    enteringMentalHealthStatus = true;
                } else if (enteringMentalHealthStatus) {
                    enteringMentalHealthStatus = false;
                    enteringSleepPatterns = true;
                } else if (enteringSleepPatterns) {
                    enteringSleepPatterns = false;
                    enteringPrimaryContactName = true;
                } else if (enteringPrimaryContactName) {
                    enteringPrimaryContactName = false;
                    enteringEmergencyPhoneNumber = true;
                } else if (enteringEmergencyPhoneNumber) {
                    enteringEmergencyPhoneNumber = false;
                    // Optionally navigate to the next screen or complete the form
                    // transitionToNextScreen();
                }
                break;

              case SDLK_BACKSPACE:
                // Handle backspace in the current input field
                if (enteringName && !name.empty()) {
                    name.pop_back();
                } else if (enteringAge && !age.empty()) {
                    age.pop_back();
                } else if (enteringGender && !gender.empty()) {
                    gender.pop_back();
                } else if (enteringBio && !bio.empty()) {
                    bio.pop_back();
                } else if (enteringFieldOfInterest && !field_of_interest.empty()) {
                    field_of_interest.pop_back();
                } else if (enteringDateOfBirth && !date_of_birth.empty()) {
                    date_of_birth.pop_back();
                } else if (enteringSpokenLanguages && !spoken_languages.empty()) {
                    spoken_languages.pop_back();
                } else if (enteringHobbies && !hobbies.empty()) {
                    hobbies.pop_back();
                } else if (enteringLinkedin && !linkedin.empty()) {
                    linkedin.pop_back();
                } else if (enteringTwitter && !twitter.empty()) {
                    twitter.pop_back();
                } else if (enteringFacebook && !facebook.empty()) {
                    facebook.pop_back();
                } else if (enteringInstagram && !instagram.empty()) {
                    instagram.pop_back();
                } else if (enteringEmail && !email.empty()) {
                    email.pop_back();
                } else if (enteringPhoneNumber && !phone_number.empty()) {
                    phone_number.pop_back();
                } else if (enteringHighestDegree && !highest_degree.empty()) {
                    highest_degree.pop_back();
                } else if (enteringMajorField && !major_field.empty()) {
                    major_field.pop_back();
                } else if (enteringHealthConditions && !health_conditions.empty()) {
                    health_conditions.pop_back();
                } else if (enteringFitnessRoutine && !fitness_routine.empty()) {
                    fitness_routine.pop_back();
                } else if (enteringMajorIllnesses && !major_illnesses.empty()) {
                    major_illnesses.pop_back();
                } else if (enteringMentalHealthStatus && !mental_health_status.empty()) {
                    mental_health_status.pop_back();
                } else if (enteringSleepPatterns && !sleep_patterns.empty()) {
                    sleep_patterns.pop_back();
                } else if (enteringPrimaryContactName && !primary_contact_name.empty()) {
                    primary_contact_name.pop_back();
                } else if (enteringRelationship && !relationship.empty()) {
                    relationship.pop_back();
                } else if (enteringEmergencyPhoneNumber && !emergency_phone_number.empty()) {
                    emergency_phone_number.pop_back();
                }
                break;
            default:
                break;
        }
    }

    if (event.type == SDL_MOUSEBUTTONDOWN || event.type == SDL_FINGERDOWN) {
        int x, y;
        if (event.type == SDL_MOUSEBUTTONDOWN) {
            x = event.button.x;
            y = event.button.y;
        } else {
            x = static_cast<int>(event.tfinger.x * Width); // Convert normalized coordinates to screen coordinates
            y = static_cast<int>(event.tfinger.y * Height);
        }

 
        // Name
        if (x >= nameBox_X && x <= nameBox_X + nameBox_WIDTH &&
            y >= nameBox_Y - scrollOffsetY && y <= nameBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringName = true;
        } else {
            enteringName = false;
        }

        // Age
        if (x >= ageBox_X && x <= ageBox_X + ageBox_WIDTH &&
            y >= ageBox_Y - scrollOffsetY && y <= ageBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringAge = true;
        } else {
            enteringAge = false;
        }

        // Gender
        if (x >= genderBox_X && x <= genderBox_X + genderBox_WIDTH &&
            y >= genderBox_Y - scrollOffsetY && y <= genderBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringGender = true;
        } else {
            enteringGender = false;
        }

        // Bio
        if (x >= bioBox_X && x <= bioBox_X + bioBox_WIDTH &&
            y >= bioBox_Y - scrollOffsetY && y <= bioBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringBio = true;
        } else {
            enteringBio = false;
        }

        // Field of Interest
        if (x >= fieldOfInterestBox_X && x <= fieldOfInterestBox_X + fieldOfInterestBox_WIDTH &&
            y >= fieldOfInterestBox_Y - scrollOffsetY && y <= fieldOfInterestBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringFieldOfInterest = true;
        } else {
            enteringFieldOfInterest = false;
        }

        // Date of Birth
        if (x >= dateOfBirthBox_X && x <= dateOfBirthBox_X + dateOfBirthBox_WIDTH &&
            y >= dateOfBirthBox_Y - scrollOffsetY && y <= dateOfBirthBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringDateOfBirth = true;
        } else {
            enteringDateOfBirth = false;
        }

        // Spoken Languages
        if (x >= spokenLanguagesBox_X && x <= spokenLanguagesBox_X + spokenLanguagesBox_WIDTH &&
            y >= spokenLanguagesBox_Y - scrollOffsetY && y <= spokenLanguagesBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringSpokenLanguages = true;
        } else {
            enteringSpokenLanguages = false;
        }

        // Hobbies
        if (x >= hobbiesBox_X && x <= hobbiesBox_X + hobbiesBox_WIDTH &&
            y >= hobbiesBox_Y - scrollOffsetY && y <= hobbiesBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringHobbies = true;
        } else {
            enteringHobbies = false;
        }

        // LinkedIn
        if (x >= linkedinBox_X && x <= linkedinBox_X + linkedinBox_WIDTH &&
            y >= linkedinBox_Y - scrollOffsetY && y <= linkedinBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringLinkedin = true;
        } else {
            enteringLinkedin = false;
        }

        // Twitter
        if (x >= twitterBox_X && x <= twitterBox_X + twitterBox_WIDTH &&
            y >= twitterBox_Y - scrollOffsetY && y <= twitterBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringTwitter = true;
        } else {
            enteringTwitter = false;
        }

        // Facebook
        if (x >= facebookBox_X && x <= facebookBox_X + facebookBox_WIDTH &&
            y >= facebookBox_Y - scrollOffsetY && y <= facebookBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringFacebook = true;
        } else {
            enteringFacebook = false;
        }

        // Instagram
        if (x >= instagramBox_X && x <= instagramBox_X + instagramBox_WIDTH &&
            y >= instagramBox_Y - scrollOffsetY && y <= instagramBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringInstagram = true;
        } else {
            enteringInstagram = false;
        }

        // Email
        if (x >= emailBox_X && x <= emailBox_X + emailBox_WIDTH &&
            y >= emailBox_Y - scrollOffsetY && y <= emailBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringEmail = true;
        } else {
            enteringEmail = false;
        }

        // Phone Number
        if (x >= phoneNumberBox_X && x <= phoneNumberBox_X + phoneNumberBox_WIDTH &&
            y >= phoneNumberBox_Y - scrollOffsetY && y <= phoneNumberBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringPhoneNumber = true;
        } else {
            enteringPhoneNumber = false;
        }

        // Highest Degree
        if (x >= highestDegreeBox_X && x <= highestDegreeBox_X + highestDegreeBox_WIDTH &&
            y >= highestDegreeBox_Y - scrollOffsetY && y <= highestDegreeBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringHighestDegree = true;
        } else {
            enteringHighestDegree = false;
        }

        // Major Field
        if (x >= majorFieldBox_X && x <= majorFieldBox_X + majorFieldBox_WIDTH &&
            y >= majorFieldBox_Y - scrollOffsetY && y <= majorFieldBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringMajorField = true;
        } else {
            enteringMajorField = false;
        }

        // Health Conditions
        if (x >= healthConditionsBox_X && x <= healthConditionsBox_X + healthConditionsBox_WIDTH &&
            y >= healthConditionsBox_Y - scrollOffsetY && y <= healthConditionsBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringHealthConditions = true;
        } else {
            enteringHealthConditions = false;
        }

        // Fitness Routine
        if (x >= fitnessRoutineBox_X && x <= fitnessRoutineBox_X + fitnessRoutineBox_WIDTH &&
            y >= fitnessRoutineBox_Y - scrollOffsetY && y <= fitnessRoutineBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringFitnessRoutine = true;
        } else {
            enteringFitnessRoutine = false;
        }

        // Major Illnesses
        if (x >= majorIllnessesBox_X && x <= majorIllnessesBox_X + majorIllnessesBox_WIDTH &&
            y >= majorIllnessesBox_Y - scrollOffsetY && y <= majorIllnessesBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringMajorIllnesses = true;
        } else {
            enteringMajorIllnesses = false;
        }

        // Mental Health Status
        if (x >= mentalHealthStatusBox_X && x <= mentalHealthStatusBox_X + mentalHealthStatusBox_WIDTH &&
            y >= mentalHealthStatusBox_Y - scrollOffsetY && y <= mentalHealthStatusBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringMentalHealthStatus = true;
        } else {
            enteringMentalHealthStatus = false;
        }

        // Sleep Patterns
        if (x >= sleepPatternsBox_X && x <= sleepPatternsBox_X + sleepPatternsBox_WIDTH &&
            y >= sleepPatternsBox_Y - scrollOffsetY && y <= sleepPatternsBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringSleepPatterns = true;
        } else {
            enteringSleepPatterns = false;
        }

        // Primary Contact Name
        if (x >= primaryContactNameBox_X && x <= primaryContactNameBox_X + primaryContactNameBox_WIDTH &&
            y >= primaryContactNameBox_Y - scrollOffsetY && y <= primaryContactNameBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringPrimaryContactName = true;
        } else {
            enteringPrimaryContactName = false;
        }

        // Relationship
        if (x >= relationshipBox_X && x <= relationshipBox_X + relationshipBox_WIDTH &&
            y >= relationshipBox_Y - scrollOffsetY && y <= relationshipBox_Y - scrollOffsetY + inputBoxHeight) {
            enteringRelationship = true;
        } else {
            enteringRelationship = false;
        }

        // Emergency Phone Number
        if (x >= emergencyPhoneNumberBox_X && x <= emergencyPhoneNumberBox_X + inputBoxHeight &&
            y >= emergencyPhoneNumberBox_Y - scrollOffsetY && y <= emergencyPhoneNumberBox_Y - scrollOffsetY + emergencyPhoneNumberBox_WIDTH) {
            enteringEmergencyPhoneNumber = true;
        } else {
            enteringEmergencyPhoneNumber = false;
        }


        // Check for click events on the underlined text
        if (x >= xConsentForms && x <= xConsentForms + textWidthConsentForms &&
            y >= yConsentForms - scrollOffsetY && y <= yConsentForms - scrollOffsetY + textHeightConsentForms) {
             changeState(CONSENT_FORMS_SCREEN); 
        }

        if (x >= xLicenseAgreements && x <= xLicenseAgreements + textWidthLicenseAgreements &&
            y >= yLicenseAgreements - scrollOffsetY && y <= yLicenseAgreements - scrollOffsetY + textHeightLicenseAgreements) {
             changeState(LICENSE_AGREEMENTS_SCREEN); 
        }

        if (x >= xTermsOfService && x <= xTermsOfService + textWidthTermsOfService &&
            y >= yTermsOfService - scrollOffsetY && y <= yTermsOfService - scrollOffsetY + textHeightTermsOfService) {
            changeState(TERMS_OF_SERVICE_SCREEN); 
        }

        // Check for click events on the checkboxes
        if (x >= consentFormsBox_X && x <= consentFormsBox_X + checkboxSize2 &&
            y >= consentFormsBox_Y - scrollOffsetY && y <= consentFormsBox_Y - scrollOffsetY + checkboxSize2) {
            isCheckbox1Checked = !isCheckbox1Checked;
            printf("Checkbox 1 state toggled: %d\n", isCheckbox1Checked);
        }

        if (x >= licenseAgreementsBox_X && x <= licenseAgreementsBox_X + checkboxSize2 &&
            y >= licenseAgreementsBox_Y - scrollOffsetY && y <= licenseAgreementsBox_Y - scrollOffsetY + checkboxSize2) {
            isCheckbox2Checked = !isCheckbox2Checked;
            printf("Checkbox 2 state toggled: %d\n", isCheckbox2Checked);
        }

        if (x >= termsOfServiceBox_X && x <= termsOfServiceBox_X + checkboxSize2 &&
            y >= termsOfServiceBox_Y - scrollOffsetY && y <= termsOfServiceBox_Y - scrollOffsetY + checkboxSize2) {
            isCheckbox3Checked = !isCheckbox3Checked;
            printf("Checkbox 3 state toggled: %d\n", isCheckbox3Checked);
        }

//if click on personalInfoText then it should call that i think so i need to change it 
 SDL_GetMouseState(&x, &y);

        // Debugging: Print the mouse coordinates
        std::cout << "Mouse click at (" << x << ", " << y << ")" << std::endl;
    // Check for clicks on different headings and toggle the visibility of details accordingly
     // Check if any detail is already being shown
    bool anyDetailShown = showPersonalInfoDetails || showSocialMediaDetails || showContactInfoDetails ||
                          showEducationInfoDetails || showHealthWellnessDetails || showCognitiveReportsDetails ||
                          showCustomContentDetails || showEmergencyContactDetails || showLegalConsentDetails;
// bool anyTextShown = showpersonalInfoText || showSocialMediaText || showcontactInfoText ||
//                         showeducationInfoText || showhealthWellnessText || showcognitiveReportsText ||
//                         showcustomContentText || showemergencyContactText || showlegalConsentText;
    


//iam not getting it how to solve this problem when its like recording allof the previous clicks of mine and making htose texts active too when i go tot the next one i have no idea why its happening


    if (isClickOnHeading(x, y, xPersonalInfo, yPersonalInfo - scrollOffsetY, textWidthPersonalInfo, textHeightPersonalInfo)) {
        if (!showPersonalInfoDetails && !anyDetailShown) {
            showPersonalInfoDetails = true;
        } else if (showPersonalInfoDetails) {
            showPersonalInfoDetails = false;
        }
    } else if (isClickOnHeading(x, y, xSocialMedia, ySocialMedia - scrollOffsetY, textWidthSocialMedia, textHeightSocialMedia)) {
        if (!showSocialMediaDetails && !anyDetailShown) {
            showSocialMediaDetails = true;
        } else if (showSocialMediaDetails) {
            showSocialMediaDetails = false;
        }
    } else if (isClickOnHeading(x, y, xContactInfo, yContactInfo - scrollOffsetY, textWidthContactInfo, textHeightContactInfo)) {
        if (!showContactInfoDetails && !anyDetailShown) {
            showContactInfoDetails = true;
        } else if (showContactInfoDetails) {
            showContactInfoDetails = false;
        }
    } else if (isClickOnHeading(x, y, xEducationInfo, yEducationInfo - scrollOffsetY, textWidthEducationInfo, textHeightEducationInfo)) {
        if (!showEducationInfoDetails && !anyDetailShown) {
            showEducationInfoDetails = true;
        } else if (showEducationInfoDetails) {
            showEducationInfoDetails = false;
        }
    } else if (isClickOnHeading(x, y, xHealthWellness, yHealthWellness - scrollOffsetY, textWidthHealthWellness, textHeightHealthWellness)) {
        if (!showHealthWellnessDetails && !anyDetailShown) {
            showHealthWellnessDetails = true;
        } else if (showHealthWellnessDetails) {
            showHealthWellnessDetails = false;
        }
    } else if (isClickOnHeading(x, y, xCognitiveReports, yCognitiveReports - scrollOffsetY, textWidthCognitiveReports, textHeightCognitiveReports)) {
        if (!showCognitiveReportsDetails && !anyDetailShown) {
            showCognitiveReportsDetails = true;
        } else if (showCognitiveReportsDetails) {
            showCognitiveReportsDetails = false;
        }
    } else if (isClickOnHeading(x, y, xCustomContent, yCustomContent - scrollOffsetY, textWidthCustomContent, textHeightCustomContent)) {
        if (!showCustomContentDetails && !anyDetailShown) {
            showCustomContentDetails = true;
        } else if (showCustomContentDetails) {
            showCustomContentDetails = false;
        }
    } else if (isClickOnHeading(x, y, xEmergencyContact, yEmergencyContact - scrollOffsetY, textWidthEmergencyContact, textHeightEmergencyContact)) {
        if (!showEmergencyContactDetails && !anyDetailShown) {
            showEmergencyContactDetails = true;
        } else if (showEmergencyContactDetails) {
            showEmergencyContactDetails = false;
        }
    } else if (isClickOnHeading(x, y, xLegalConsent, yLegalConsent - scrollOffsetY, textWidthLegalConsent, textHeightLegalConsent)) {
        if (!showLegalConsentDetails && !anyDetailShown) {
            showLegalConsentDetails = true;
        } else if (showLegalConsentDetails) {
            showLegalConsentDetails = false;
        }
    }

    // Update all text display flags based on the detail flags
    showpersonalInfoText = showPersonalInfoDetails;
    showsocialMediaText = showSocialMediaDetails;
    showcontactInfoText = showContactInfoDetails;
    showeducationInfoText = showEducationInfoDetails;
    showhealthWellnessText = showHealthWellnessDetails;
    showcognitiveReportsText = showCognitiveReportsDetails;
    showcustomContentText = showCustomContentDetails;
    showemergencyContactText = showEmergencyContactDetails;
    showlegalConsentText = showLegalConsentDetails;   
            
           
      
    } 
}

    


















//  if (event.type == SDL_KEYDOWN && event.key.keysym.sym == SDLK_RETURN) {
//         nfdchar_t *outPath = NULL;
//         nfdresult_t result = NFD_OpenDialog(NULL, NULL, &outPath); // Open a file dialog
//         if (result == NFD_OKAY) {
//             std::string filePath(outPath);
//             free(outPath);

//             if (enteringNeuropsychologicalAssessments) {
//                 neuropsychological_assessments = filePath;
//             } else if (enteringEEG) {
//                 eeg = filePath;
//             } else if (enteringQEEG) {
//                 qeeg = filePath;
//             } else if (enteringFMRI) {
//                 fmri = filePath;
//             } else if (enteringMRI) {
//                 mri = filePath;
//             } else if (enteringCTScan) {
//                 ct_scan = filePath;
//             } else if (enteringEvokedPotentials) {
//                 evoked_potentials = filePath;
//             } else if (enteringSleepStudies) {
//                 sleep_studies = filePath;
//             } else if (enteringCSFAnalysis) {
//                 csf_analysis = filePath;
//             } else if (enteringTextContent) {
//                 text_content = filePath;
//             } else if (enteringPdfs) {
//                 pdfs = filePath;
//             } else if (enteringImages) {
//                 images = filePath;
//             } else if (enteringVideos) {
//                 videos = filePath;
//             } else if (enteringAudio) {
//                 audio = filePath;
//             } else if (enteringSpreadsheets) {
//                 spreadsheets = filePath;
//             } else if (enteringPresentations) {
//                 presentations = filePath;
//             } else if (enteringCode) {
//                 code = filePath;
//             } else if (enteringModels) {
//                 models = filePath;
//             } else if (enteringEbooks) {
//                 ebooks = filePath;
//             }
//         } else if (result == NFD_CANCEL) {
//             // User cancelled the dialog
//         } else {
//             // Error handling
//         }
//     }




         
    

    void update() override {
       NavigationMenu:: update();
    }


bool isClickOnHeading(int mouseX, int mouseY, int headingX, int headingY, int textWidth, int textHeight) {
    return (mouseX >= headingX && mouseX <= headingX + textWidth &&
            mouseY >= headingY && mouseY <= headingY + textHeight);
}




void drawHeadings(SDL_Renderer* renderer)
{// Personal Information

}







    void render() override {
        
        
      NavigationMenu::render();




// Display Text Variables
std::string nameText = "Name" + name;
std::string ageText = "Age" + age;
std::string genderText = "Gender" + gender;
std::string bioText = "Bio" + bio;
std::string fieldOfInterestText = "Field of Interest" + field_of_interest;
std::string dateOfBirthText = "Date of Birth" + date_of_birth;
std::string spokenLanguagesText = "Spoken Languages" + spoken_languages;
std::string hobbiesText = "Hobbies" + hobbies;

std::string linkedinText = "LinkedIn" + linkedin;
std::string twitterText = "Twitter" + twitter;
std::string facebookText = "Facebook" + facebook;
std::string instagramText = "Instagram" + instagram;

std::string emailText = "Email" + email;
std::string phoneNumberText = "Phone Number" + phone_number;

std::string highestDegreeText = "Highest Degree Earned" + highest_degree;
std::string majorFieldText = "Major Field of Study" + major_field;

std::string healthConditionsText = "Health Conditions" + health_conditions;
std::string fitnessRoutineText = "Fitness Routine" + fitness_routine;
std::string majorIllnessesText = "Major Illnesses" + major_illnesses;
std::string mentalHealthStatusText = "Mental Health Status" + mental_health_status;
std::string sleepPatternsText = "Sleep Patterns" + sleep_patterns;

std::string neuropsychologicalAssessmentsText = "Neuropsychological Evaluation" + neuropsychological_assessments;
std::string eegText = "Electroencephalography" + eeg;
std::string qeegText = "Quantitative Electroencephalography" + qeeg;
std::string fmriText = "Functional Magnetic Resonance Imaging" + fmri;
std::string mriText = "Magnetic Resonance Imaging" + mri;
std::string ctScanText = "Computed Tomography" + ct_scan;
std::string evokedPotentialsText = "Evoked Potentials" + evoked_potentials;
std::string sleepStudiesText = "Polysomnography" + sleep_studies;
std::string csfAnalysisText = "Cerebrospinal Fluid Analysis" + csf_analysis;

std::string textContentText = "Text" + text_content;
std::string pdfsText = "PDFs" + pdfs;
std::string imagesText = "Images" + images;
std::string videosText = "Videos" + videos;
std::string audioText = "Audio" + audio;
std::string spreadsheetsText = "Spreadsheets" + spreadsheets;
std::string presentationsText = "Presentations" + presentations;
std::string codeText = "Code" + code;
std::string modelsText = "3D Models" + models;
std::string ebooksText = "E-books" + ebooks;

std::string primaryContactNameText = "Primary Contact Name" + primary_contact_name;
std::string relationshipText = "Relationship" + relationship;
std::string emergencyPhoneNumberText = "Phone Number" + emergency_phone_number;

std::string consentFormsText = "Consent Forms" + consent_forms;
std::string licenseAgreementsText = "License Agreements" + license_agreements;
std::string termsOfServiceText = "Terms of Service" + terms_of_service;





// Calculate Text Widths and Heights for const char* Labels
TTF_SizeText(NunitoFont, profilePhotoText, &textWidthProfilePhoto, &textHeightProfilePhoto);
TTF_SizeText(NimbusRomFont, personalInfoText, &textWidthPersonalInfo, &textHeightPersonalInfo);
TTF_SizeText(NimbusRomFont, socialMediaText, &textWidthSocialMedia, &textHeightSocialMedia);
TTF_SizeText(NimbusRomFont, contactInfoText, &textWidthContactInfo, &textHeightContactInfo);
TTF_SizeText(NimbusRomFont, educationInfoText, &textWidthEducationInfo, &textHeightEducationInfo);
TTF_SizeText(NimbusRomFont, healthWellnessText, &textWidthHealthWellness, &textHeightHealthWellness);
TTF_SizeText(NimbusRomFont, cognitiveReportsText, &textWidthCognitiveReports, &textHeightCognitiveReports);
TTF_SizeText(NimbusRomFont, customContentText, &textWidthCustomContent, &textHeightCustomContent);
TTF_SizeText(NimbusRomFont, emergencyContactText, &textWidthEmergencyContact, &textHeightEmergencyContact);
TTF_SizeText(NimbusRomFont, legalConsentText, &textWidthLegalConsent, &textHeightLegalConsent);



// Calculate Text Widths and Heights for std::string Display Texts
TTF_SizeText(NunitoFont, nameText.c_str(), &textWidthName, &textHeightName);
TTF_SizeText(NunitoFont, ageText.c_str(), &textWidthAge, &textHeightAge);
TTF_SizeText(NunitoFont, genderText.c_str(), &textWidthGender, &textHeightGender);
TTF_SizeText(NunitoFont, bioText.c_str(), &textWidthBio, &textHeightBio);
TTF_SizeText(NunitoFont, fieldOfInterestText.c_str(), &textWidthFieldOfInterest, &textHeightFieldOfInterest);
TTF_SizeText(NunitoFont, dateOfBirthText.c_str(), &textWidthDateOfBirth, &textHeightDateOfBirth);
TTF_SizeText(NunitoFont, spokenLanguagesText.c_str(), &textWidthSpokenLanguages, &textHeightSpokenLanguages);
TTF_SizeText(NunitoFont, hobbiesText.c_str(), &textWidthHobbies, &textHeightHobbies);

TTF_SizeText(NunitoFont, linkedinText.c_str(), &textWidthLinkedin, &textHeightLinkedin);
TTF_SizeText(NunitoFont, twitterText.c_str(), &textWidthTwitter, &textHeightTwitter);
TTF_SizeText(NunitoFont, facebookText.c_str(), &textWidthFacebook, &textHeightFacebook);
TTF_SizeText(NunitoFont, instagramText.c_str(), &textWidthInstagram, &textHeightInstagram);

TTF_SizeText(NunitoFont, emailText.c_str(), &textWidthEmail, &textHeightEmail);
TTF_SizeText(NunitoFont, phoneNumberText.c_str(), &textWidthPhoneNumber, &textHeightPhoneNumber);

TTF_SizeText(NunitoFont, highestDegreeText.c_str(), &textWidthHighestDegree, &textHeightHighestDegree);
TTF_SizeText(NunitoFont, majorFieldText.c_str(), &textWidthMajorField, &textHeightMajorField);

TTF_SizeText(NunitoFont, healthConditionsText.c_str(), &textWidthHealthConditions, &textHeightHealthConditions);
TTF_SizeText(NunitoFont, fitnessRoutineText.c_str(), &textWidthFitnessRoutine, &textHeightFitnessRoutine);
TTF_SizeText(NunitoFont, majorIllnessesText.c_str(), &textWidthMajorIllnesses, &textHeightMajorIllnesses);
TTF_SizeText(NunitoFont, mentalHealthStatusText.c_str(), &textWidthMentalHealthStatus, &textHeightMentalHealthStatus);
TTF_SizeText(NunitoFont, sleepPatternsText.c_str(), &textWidthSleepPatterns, &textHeightSleepPatterns);

TTF_SizeText(NunitoFont, neuropsychologicalAssessmentsText.c_str(), &textWidthNeuropsychologicalAssessments, &textHeightNeuropsychologicalAssessments);
TTF_SizeText(NunitoFont, eegText.c_str(), &textWidthEeg, &textHeightEeg);
TTF_SizeText(NunitoFont, qeegText.c_str(), &textWidthQeeg, &textHeightQeeg);
TTF_SizeText(NunitoFont, fmriText.c_str(), &textWidthFmri, &textHeightFmri);
TTF_SizeText(NunitoFont, mriText.c_str(), &textWidthMri, &textHeightMri);
TTF_SizeText(NunitoFont, ctScanText.c_str(), &textWidthCtScan, &textHeightCtScan);
TTF_SizeText(NunitoFont, evokedPotentialsText.c_str(), &textWidthEvokedPotentials, &textHeightEvokedPotentials);
TTF_SizeText(NunitoFont, sleepStudiesText.c_str(), &textWidthSleepStudies, &textHeightSleepStudies);
TTF_SizeText(NunitoFont, csfAnalysisText.c_str(), &textWidthCsfAnalysis, &textHeightCsfAnalysis);

TTF_SizeText(NunitoFont, textContentText.c_str(), &textWidthTextContent, &textHeightTextContent);
TTF_SizeText(NunitoFont, pdfsText.c_str(), &textWidthPdfs, &textHeightPdfs);
TTF_SizeText(NunitoFont, imagesText.c_str(), &textWidthImages, &textHeightImages);
TTF_SizeText(NunitoFont, videosText.c_str(), &textWidthVideos, &textHeightVideos);
TTF_SizeText(NunitoFont, audioText.c_str(), &textWidthAudio, &textHeightAudio);
TTF_SizeText(NunitoFont, spreadsheetsText.c_str(), &textWidthSpreadsheets, &textHeightSpreadsheets);
TTF_SizeText(NunitoFont, presentationsText.c_str(), &textWidthPresentations, &textHeightPresentations);
TTF_SizeText(NunitoFont, codeText.c_str(), &textWidthCode, &textHeightCode);
TTF_SizeText(NunitoFont, modelsText.c_str(), &textWidthModels, &textHeightModels);
TTF_SizeText(NunitoFont, ebooksText.c_str(), &textWidthEbooks, &textHeightEbooks);

TTF_SizeText(NunitoFont, primaryContactNameText.c_str(), &textWidthPrimaryContactName, &textHeightPrimaryContactName);
TTF_SizeText(NunitoFont, relationshipText.c_str(), &textWidthRelationship, &textHeightRelationship);
TTF_SizeText(NunitoFont, emergencyPhoneNumberText.c_str(), &textWidthEmergencyPhoneNumber, &textHeightEmergencyPhoneNumber);

TTF_SizeText(NunitoFont, consentFormsText.c_str(), &textWidthConsentForms, &textHeightConsentForms);
TTF_SizeText(NunitoFont, licenseAgreementsText.c_str(), &textWidthLicenseAgreements, &textHeightLicenseAgreements);
TTF_SizeText(NunitoFont, termsOfServiceText.c_str(), &textWidthTermsOfService, &textHeightTermsOfService);

// Rendering Text Fields

// Profile Photo

    // Set draw color for the circle (white)
    SDL_SetRenderDrawColor(renderer, 255, 255, 255, 255);
 // Draw the circle at the specified position
    DrawCircle(renderer, centerX, centerY- scrollOffsetY, circleradius);



renderText(profilePhotoText, xProfilePhoto, yProfilePhoto- scrollOffsetY, white, NunitoFont, renderer);



 if (!showPersonalInfoDetails && !showSocialMediaDetails&& 
 !showContactInfoDetails &&
     !showEducationInfoDetails &&
     !showHealthWellnessDetails &&
     !showCognitiveReportsDetails&&
     !showCustomContentDetails&&
     !showEmergencyContactDetails&&
     !showLegalConsentDetails){


showpersonalInfoText= true;
showsocialMediaText= true;
showcontactInfoText= true;
showeducationInfoText= true;
showhealthWellnessText= true;
showcognitiveReportsText= true;
showcustomContentText= true;
showemergencyContactText= true;
showlegalConsentText= true;

    }


    
 if (showpersonalInfoText){
renderTextUnderlined(personalInfoText, xPersonalInfo, yPersonalInfo - scrollOffsetY, white, NimbusRomFont, renderer);}

if (showsocialMediaText){
// Social Media Profiles
 renderTextUnderlined(socialMediaText, xSocialMedia, ySocialMedia- scrollOffsetY, white, NimbusRomFont, renderer);}
 
if (showcontactInfoText){
// Contact Information
 renderTextUnderlined(contactInfoText, xContactInfo, yContactInfo- scrollOffsetY, white, NimbusRomFont, renderer);}
if (showeducationInfoText){
// Education Information
 renderTextUnderlined(educationInfoText, xEducationInfo, yEducationInfo- scrollOffsetY, white, NimbusRomFont, renderer);}
if (showhealthWellnessText){
// Health and Wellness
 renderTextUnderlined(healthWellnessText, xHealthWellness, yHealthWellness- scrollOffsetY, white, NimbusRomFont, renderer);}
if (showcognitiveReportsText){
// Cognitive Reports
 renderTextUnderlined(cognitiveReportsText, xCognitiveReports, yCognitiveReports- scrollOffsetY, white, NimbusRomFont, renderer);}
if (showcustomContentText){
// Custom Content
 renderTextUnderlined(customContentText, xCustomContent, yCustomContent- scrollOffsetY, white, NimbusRomFont, renderer);}
if (showemergencyContactText){
// Emergency Contact Information
 renderTextUnderlined(emergencyContactText, xEmergencyContact, yEmergencyContact- scrollOffsetY, white, NimbusRomFont, renderer);}
if (showlegalConsentText){
// Legal and Consent
 renderTextUnderlined(legalConsentText, xLegalConsent, yLegalConsent- scrollOffsetY, white, NimbusRomFont, renderer);}

    
/////////////////////////////////////////////////
if (showsocialMediaText2){
// Social Media Profiles
 renderTextUnderlined(socialMediaText, xSocialMedia, ySocialMedia2- scrollOffsetY, white, NimbusRomFont, renderer);}
 
if (showcontactInfoText3){
// Contact Information
 renderTextUnderlined(contactInfoText, xContactInfo, yContactInfo3- scrollOffsetY, white, NimbusRomFont, renderer);}
if (showeducationInfoText4){
// Education Information
 renderTextUnderlined(educationInfoText, xEducationInfo, yEducationInfo4- scrollOffsetY, white, NimbusRomFont, renderer);}
if (showhealthWellnessText5){
// Health and Wellness
 renderTextUnderlined(healthWellnessText, xHealthWellness, yHealthWellness5- scrollOffsetY, white, NimbusRomFont, renderer);}
if (showcognitiveReportsText6){
// Cognitive Reports
 renderTextUnderlined(cognitiveReportsText, xCognitiveReports, yCognitiveReports6- scrollOffsetY, white, NimbusRomFont, renderer);}
if (showcustomContentText7){
// Custom Content
 renderTextUnderlined(customContentText, xCustomContent, yCustomContent7- scrollOffsetY, white, NimbusRomFont, renderer);}
if (showemergencyContactText8){
// Emergency Contact Information
 renderTextUnderlined(emergencyContactText, xEmergencyContact, yEmergencyContact8- scrollOffsetY, white, NimbusRomFont, renderer);}
if (showlegalConsentText9){
// Legal and Consent
 renderTextUnderlined(legalConsentText, xLegalConsent, yLegalConsent9- scrollOffsetY, white, NimbusRomFont, renderer);}

    






    if (showPersonalInfoDetails) {
        showpersonalInfoText= true;
       


// Social Media Profiles
 renderText(socialMediaText, xSocialMedia, ySocialMedia1- scrollOffsetY, white, NimbusRomFont, renderer);

// Contact Information
 renderText(contactInfoText, xContactInfo, yContactInfo1- scrollOffsetY, white, NimbusRomFont, renderer);

// Education Information
 renderText(educationInfoText, xEducationInfo, yEducationInfo1- scrollOffsetY, white, NimbusRomFont, renderer);

// Health and Wellness
 renderText(healthWellnessText, xHealthWellness, yHealthWellness1- scrollOffsetY, white, NimbusRomFont, renderer);

// Cognitive Reports
 renderText(cognitiveReportsText, xCognitiveReports, yCognitiveReports1- scrollOffsetY, white, NimbusRomFont, renderer);

// Custom Content
 renderText(customContentText, xCustomContent, yCustomContent1- scrollOffsetY, white, NimbusRomFont, renderer);

// Emergency Contact Information
 renderText(emergencyContactText, xEmergencyContact, yEmergencyContact1- scrollOffsetY, white, NimbusRomFont, renderer);

// Legal and Consent
 renderText(legalConsentText, xLegalConsent, yLegalConsent1- scrollOffsetY, white, NimbusRomFont, renderer);

    






        // Display Text Variables
        renderText("Name", xName, yName - scrollOffsetY, white, NunitoFont, renderer);
        renderText("Age", xAge, yAge - scrollOffsetY, white, NunitoFont, renderer);
        renderText("Gender", xGender, yGender - scrollOffsetY, white, NunitoFont, renderer);
        renderText("Bio", xBio, yBio - scrollOffsetY, white, NunitoFont, renderer);
        renderText("Field of Interest", xFieldOfInterest, yFieldOfInterest - scrollOffsetY, white, NunitoFont, renderer);
        renderText("Date of Birth", xDateOfBirth, yDateOfBirth - scrollOffsetY, white, NunitoFont, renderer);
        renderText("Spoken Languages", xSpokenLanguages, ySpokenLanguages - scrollOffsetY, white, NunitoFont, renderer);
        renderText("Hobbies", xHobbies, yHobbies - scrollOffsetY, white, NunitoFont, renderer);

        renderRoundedRect(renderer, nameBox_X, nameBox_Y - scrollOffsetY, nameBox_WIDTH, inputBoxHeight, radius, white);
        renderRoundedRect(renderer, ageBox_X, ageBox_Y - scrollOffsetY, ageBox_WIDTH, inputBoxHeight, radius, white);
        renderRoundedRect(renderer, genderBox_X, genderBox_Y - scrollOffsetY, genderBox_WIDTH, inputBoxHeight, radius, white);
        renderRoundedRect(renderer, bioBox_X, bioBox_Y - scrollOffsetY, bioBox_WIDTH, inputBoxHeight, radius, white);
        renderRoundedRect(renderer, fieldOfInterestBox_X, fieldOfInterestBox_Y - scrollOffsetY, fieldOfInterestBox_WIDTH, inputBoxHeight, radius, white);
        renderRoundedRect(renderer, dateOfBirthBox_X, dateOfBirthBox_Y - scrollOffsetY, dateOfBirthBox_WIDTH, inputBoxHeight, radius, white);
        renderRoundedRect(renderer, spokenLanguagesBox_X, spokenLanguagesBox_Y - scrollOffsetY, spokenLanguagesBox_WIDTH, inputBoxHeight, radius, white);
        renderRoundedRect(renderer, hobbiesBox_X, hobbiesBox_Y - scrollOffsetY, hobbiesBox_WIDTH, inputBoxHeight, radius, white);

        // Name
        if (enteringName && !name.empty())
        {
            renderText(name.c_str(), nameBox_X + offset, nameBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (name.empty()) {
        renderRoundedRect(renderer, nameBox_X, nameBox_Y - scrollOffsetY, nameBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(name.c_str(), nameBox_X + offset, nameBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}

// Age
if (enteringAge && !age.empty()) {
    renderText(age.c_str(), ageBox_X + offset, ageBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (age.empty()) {
        renderRoundedRect(renderer, ageBox_X, ageBox_Y - scrollOffsetY, ageBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(age.c_str(), ageBox_X + offset, ageBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}

// Gender
if (enteringGender && !gender.empty()) {
    renderText(gender.c_str(), genderBox_X + offset, genderBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (gender.empty()) {
        renderRoundedRect(renderer, genderBox_X, genderBox_Y - scrollOffsetY, genderBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(gender.c_str(), genderBox_X + offset, genderBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}

// Bio
if (enteringBio && !bio.empty()) {
    renderText(bio.c_str(), bioBox_X + offset, bioBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (bio.empty()) {
        renderRoundedRect(renderer, bioBox_X, bioBox_Y - scrollOffsetY, bioBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(bio.c_str(), bioBox_X + offset, bioBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}

// Field of Interest
if (enteringFieldOfInterest && !field_of_interest.empty()) {
    renderText(field_of_interest.c_str(), fieldOfInterestBox_X + offset, fieldOfInterestBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (field_of_interest.empty()) {
        renderRoundedRect(renderer, fieldOfInterestBox_X, fieldOfInterestBox_Y - scrollOffsetY, fieldOfInterestBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(field_of_interest.c_str(), fieldOfInterestBox_X + offset, fieldOfInterestBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}

// Date of Birth
if (enteringDateOfBirth && !date_of_birth.empty()) {
    renderText(date_of_birth.c_str(), dateOfBirthBox_X + offset, dateOfBirthBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (date_of_birth.empty()) {
        renderRoundedRect(renderer, dateOfBirthBox_X, dateOfBirthBox_Y - scrollOffsetY, dateOfBirthBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(date_of_birth.c_str(), dateOfBirthBox_X + offset, dateOfBirthBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}

// Spoken Languages
if (enteringSpokenLanguages && !spoken_languages.empty()) {
    renderText(spoken_languages.c_str(), spokenLanguagesBox_X + offset, spokenLanguagesBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (spoken_languages.empty()) {
        renderRoundedRect(renderer, spokenLanguagesBox_X, spokenLanguagesBox_Y - scrollOffsetY, spokenLanguagesBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(spoken_languages.c_str(), spokenLanguagesBox_X + offset, spokenLanguagesBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}

// Hobbies
if (enteringHobbies && !hobbies.empty()) {
    renderText(hobbies.c_str(), hobbiesBox_X + offset, hobbiesBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (hobbies.empty()) {
        renderRoundedRect(renderer, hobbiesBox_X, hobbiesBox_Y - scrollOffsetY, hobbiesBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(hobbies.c_str(), hobbiesBox_X + offset, hobbiesBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}


    }
    
    

 if (showSocialMediaDetails) {

  
 
showsocialMediaText2= true;  


renderText(personalInfoText, xPersonalInfo, yPersonalInfo2 - scrollOffsetY, white, NimbusRomFont, renderer);

// Contact Information
 renderText(contactInfoText, xContactInfo, yContactInfo2- scrollOffsetY, white, NimbusRomFont, renderer);

// Education Information
 renderText(educationInfoText, xEducationInfo, yEducationInfo2- scrollOffsetY, white, NimbusRomFont, renderer);

// Health and Wellness
 renderText(healthWellnessText, xHealthWellness, yHealthWellness2- scrollOffsetY, white, NimbusRomFont, renderer);

// Cognitive Reports
 renderText(cognitiveReportsText, xCognitiveReports, yCognitiveReports2- scrollOffsetY, white, NimbusRomFont, renderer);

// Custom Content
 renderText(customContentText, xCustomContent, yCustomContent2- scrollOffsetY, white, NimbusRomFont, renderer);

// Emergency Contact Information
 renderText(emergencyContactText, xEmergencyContact, yEmergencyContact2- scrollOffsetY, white, NimbusRomFont, renderer);

// Legal and Consent
 renderText(legalConsentText, xLegalConsent, yLegalConsent2- scrollOffsetY, white, NimbusRomFont, renderer);


renderText("LinkedIn", xLinkedin, yLinkedin- scrollOffsetY, white, NunitoFont, renderer);
renderText("Twitter", xTwitter, yTwitter- scrollOffsetY, white, NunitoFont, renderer);
renderText("Facebook", xFacebook, yFacebook- scrollOffsetY, white, NunitoFont, renderer);
renderText("Instagram", xInstagram, yInstagram- scrollOffsetY, white, NunitoFont, renderer);


renderRoundedRect(renderer, linkedinBox_X, linkedinBox_Y- scrollOffsetY, linkedinBox_WIDTH, inputBoxHeight, radius, white);
renderRoundedRect(renderer, twitterBox_X, twitterBox_Y- scrollOffsetY, twitterBox_WIDTH, inputBoxHeight, radius, white);
renderRoundedRect(renderer, facebookBox_X, facebookBox_Y- scrollOffsetY, facebookBox_WIDTH, inputBoxHeight, radius, white);
renderRoundedRect(renderer, instagramBox_X, instagramBox_Y- scrollOffsetY, instagramBox_WIDTH, inputBoxHeight, radius, white);

// LinkedIn
if (enteringLinkedin && !linkedin.empty()) {
    renderText(linkedin.c_str(), linkedinBox_X + offset, linkedinBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (linkedin.empty()) {
        renderRoundedRect(renderer, linkedinBox_X, linkedinBox_Y - scrollOffsetY, linkedinBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(linkedin.c_str(), linkedinBox_X + offset, linkedinBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}

// Twitter
if (enteringTwitter && !twitter.empty()) {
    renderText(twitter.c_str(), twitterBox_X + offset, twitterBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (twitter.empty()) {
        renderRoundedRect(renderer, twitterBox_X, twitterBox_Y - scrollOffsetY, twitterBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(twitter.c_str(), twitterBox_X + offset, twitterBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}

// Facebook
if (enteringFacebook && !facebook.empty()) {
    renderText(facebook.c_str(), facebookBox_X + offset, facebookBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (facebook.empty()) {
        renderRoundedRect(renderer, facebookBox_X, facebookBox_Y - scrollOffsetY, facebookBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(facebook.c_str(), facebookBox_X + offset, facebookBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}

// Instagram
if (enteringInstagram && !instagram.empty()) {
    renderText(instagram.c_str(), instagramBox_X + offset, instagramBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (instagram.empty()) {
        renderRoundedRect(renderer, instagramBox_X, instagramBox_Y - scrollOffsetY, instagramBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(instagram.c_str(), instagramBox_X + offset, instagramBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}
}
    if (showContactInfoDetails) {



showcontactInfoText3= true;

renderText(personalInfoText, xPersonalInfo, yPersonalInfo3 - scrollOffsetY, white, NimbusRomFont, renderer);

// Social Media Profiles
 renderText(socialMediaText, xSocialMedia, ySocialMedia3- scrollOffsetY, white, NimbusRomFont, renderer);


// Education Information
 renderText(educationInfoText, xEducationInfo, yEducationInfo3- scrollOffsetY, white, NimbusRomFont, renderer);

// Health and Wellness
 renderText(healthWellnessText, xHealthWellness, yHealthWellness3- scrollOffsetY, white, NimbusRomFont, renderer);

// Cognitive Reports
 renderText(cognitiveReportsText, xCognitiveReports, yCognitiveReports3- scrollOffsetY, white, NimbusRomFont, renderer);

// Custom Content
 renderText(customContentText, xCustomContent, yCustomContent3- scrollOffsetY, white, NimbusRomFont, renderer);

// Emergency Contact Information
 renderText(emergencyContactText, xEmergencyContact, yEmergencyContact3- scrollOffsetY, white, NimbusRomFont, renderer);

// Legal and Consent
 renderText(legalConsentText, xLegalConsent, yLegalConsent3- scrollOffsetY, white, NimbusRomFont, renderer);

renderText("Email", xEmail, yEmail- scrollOffsetY, white, NunitoFont, renderer);
renderText("Phone Number", xPhoneNumber, yPhoneNumber- scrollOffsetY, white, NunitoFont, renderer);


renderRoundedRect(renderer, emailBox_X, emailBox_Y- scrollOffsetY, emailBox_WIDTH, inputBoxHeight, radius, white);
renderRoundedRect(renderer, phoneNumberBox_X, phoneNumberBox_Y- scrollOffsetY, phoneNumberBox_WIDTH, inputBoxHeight, radius, white);


// Email
if (enteringEmail && !email.empty()) {
    renderText(email.c_str(), emailBox_X + offset, emailBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (email.empty()) {
        renderRoundedRect(renderer, emailBox_X, emailBox_Y - scrollOffsetY, emailBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(email.c_str(), emailBox_X + offset, emailBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}

// Phone Number
if (enteringPhoneNumber && !phone_number.empty()) {
    renderText(phone_number.c_str(), phoneNumberBox_X + offset, phoneNumberBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (phone_number.empty()) {
        renderRoundedRect(renderer, phoneNumberBox_X, phoneNumberBox_Y - scrollOffsetY, phoneNumberBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(phone_number.c_str(), phoneNumberBox_X + offset, phoneNumberBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}

 }

    if (showEducationInfoDetails) {
    


 showeducationInfoText4= true;  

renderText(personalInfoText, xPersonalInfo, yPersonalInfo4 - scrollOffsetY, white, NimbusRomFont, renderer);

// Social Media Profiles
 renderText(socialMediaText, xSocialMedia, ySocialMedia4- scrollOffsetY, white, NimbusRomFont, renderer);

// Contact Information
 renderText(contactInfoText, xContactInfo, yContactInfo4- scrollOffsetY, white, NimbusRomFont, renderer);


// Health and Wellness
 renderText(healthWellnessText, xHealthWellness, yHealthWellness4- scrollOffsetY, white, NimbusRomFont, renderer);

// Cognitive Reports
 renderText(cognitiveReportsText, xCognitiveReports, yCognitiveReports4- scrollOffsetY, white, NimbusRomFont, renderer);

// Custom Content
 renderText(customContentText, xCustomContent, yCustomContent4- scrollOffsetY, white, NimbusRomFont, renderer);

// Emergency Contact Information
 renderText(emergencyContactText, xEmergencyContact, yEmergencyContact4- scrollOffsetY, white, NimbusRomFont, renderer);

// Legal and Consent
 renderText(legalConsentText, xLegalConsent, yLegalConsent4- scrollOffsetY, white, NimbusRomFont, renderer);
renderText("Highest Degree Earned" , xHighestDegree, yHighestDegree- scrollOffsetY, white, NunitoFont, renderer);
renderText("Major Field of Study", xMajorField, yMajorField- scrollOffsetY, white, NunitoFont, renderer);


renderRoundedRect(renderer, highestDegreeBox_X, highestDegreeBox_Y- scrollOffsetY, highestDegreeBox_WIDTH, inputBoxHeight, radius, white);
renderRoundedRect(renderer, majorFieldBox_X, majorFieldBox_Y- scrollOffsetY, majorFieldBox_WIDTH, inputBoxHeight, radius, white);
















// Highest Degree
if (enteringHighestDegree && !highest_degree.empty()) {
    renderText(highest_degree.c_str(), highestDegreeBox_X + offset, highestDegreeBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (highest_degree.empty()) {
        renderRoundedRect(renderer, highestDegreeBox_X, highestDegreeBox_Y - scrollOffsetY, highestDegreeBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(highest_degree.c_str(), highestDegreeBox_X + offset, highestDegreeBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}

// Major Field
if (enteringMajorField && !major_field.empty()) {
    renderText(major_field.c_str(), majorFieldBox_X + offset, majorFieldBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (major_field.empty()) {
        renderRoundedRect(renderer, majorFieldBox_X, majorFieldBox_Y - scrollOffsetY, majorFieldBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(major_field.c_str(), majorFieldBox_X + offset, majorFieldBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}
}

    if (showHealthWellnessDetails) {
 
        

 showhealthWellnessText5= true;
renderText(personalInfoText, xPersonalInfo, yPersonalInfo5 - scrollOffsetY, white, NimbusRomFont, renderer);

// Social Media Profiles
 renderText(socialMediaText, xSocialMedia, ySocialMedia5- scrollOffsetY, white, NimbusRomFont, renderer);

// Contact Information
 renderText(contactInfoText, xContactInfo, yContactInfo5- scrollOffsetY, white, NimbusRomFont, renderer);

// Education Information
 renderText(educationInfoText, xEducationInfo, yEducationInfo5- scrollOffsetY, white, NimbusRomFont, renderer);


// Cognitive Reports
 renderText(cognitiveReportsText, xCognitiveReports, yCognitiveReports5- scrollOffsetY, white, NimbusRomFont, renderer);

// Custom Content
 renderText(customContentText, xCustomContent, yCustomContent5- scrollOffsetY, white, NimbusRomFont, renderer);

// Emergency Contact Information
 renderText(emergencyContactText, xEmergencyContact, yEmergencyContact5- scrollOffsetY, white, NimbusRomFont, renderer);

// Legal and Consent
 renderText(legalConsentText, xLegalConsent, yLegalConsent5- scrollOffsetY, white, NimbusRomFont, renderer);



renderText("Health Conditions", xHealthConditions, yHealthConditions- scrollOffsetY, white, NunitoFont, renderer);
renderText("Fitness Routine", xFitnessRoutine, yFitnessRoutine- scrollOffsetY, white, NunitoFont, renderer);
renderText("Major Illnesses", xMajorIllnesses, yMajorIllnesses- scrollOffsetY, white, NunitoFont, renderer);
renderText("Mental Health Status", xMentalHealthStatus, yMentalHealthStatus- scrollOffsetY, white, NunitoFont, renderer);
renderText("Sleep Patterns", xSleepPatterns, ySleepPatterns- scrollOffsetY, white, NunitoFont, renderer);
 
 
renderRoundedRect(renderer, healthConditionsBox_X, healthConditionsBox_Y- scrollOffsetY, healthConditionsBox_WIDTH, inputBoxHeight, radius, white);
renderRoundedRect(renderer, fitnessRoutineBox_X, fitnessRoutineBox_Y- scrollOffsetY, fitnessRoutineBox_WIDTH, inputBoxHeight, radius, white);
renderRoundedRect(renderer, majorIllnessesBox_X, majorIllnessesBox_Y- scrollOffsetY, majorIllnessesBox_WIDTH, inputBoxHeight, radius, white);
renderRoundedRect(renderer, mentalHealthStatusBox_X, mentalHealthStatusBox_Y- scrollOffsetY, mentalHealthStatusBox_WIDTH, inputBoxHeight, radius, white);
renderRoundedRect(renderer, sleepPatternsBox_X, sleepPatternsBox_Y- scrollOffsetY, sleepPatternsBox_WIDTH, inputBoxHeight, radius, white);
 
// Health Conditions
if (enteringHealthConditions && !health_conditions.empty()) {
    renderText(health_conditions.c_str(), healthConditionsBox_X + offset, healthConditionsBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (health_conditions.empty()) {
        renderRoundedRect(renderer, healthConditionsBox_X, healthConditionsBox_Y - scrollOffsetY, healthConditionsBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(health_conditions.c_str(), healthConditionsBox_X + offset, healthConditionsBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}

// Fitness Routine
if (enteringFitnessRoutine && !fitness_routine.empty()) {
    renderText(fitness_routine.c_str(), fitnessRoutineBox_X + offset, fitnessRoutineBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (fitness_routine.empty()) {
        renderRoundedRect(renderer, fitnessRoutineBox_X, fitnessRoutineBox_Y - scrollOffsetY, fitnessRoutineBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(fitness_routine.c_str(), fitnessRoutineBox_X + offset, fitnessRoutineBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}

// Major Illnesses
if (enteringMajorIllnesses && !major_illnesses.empty()) {
    renderText(major_illnesses.c_str(), majorIllnessesBox_X + offset, majorIllnessesBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (major_illnesses.empty()) {
        renderRoundedRect(renderer, majorIllnessesBox_X, majorIllnessesBox_Y - scrollOffsetY, majorIllnessesBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(major_illnesses.c_str(), majorIllnessesBox_X + offset, majorIllnessesBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}

// Mental Health Status
if (enteringMentalHealthStatus && !mental_health_status.empty()) {
    renderText(mental_health_status.c_str(), mentalHealthStatusBox_X + offset, mentalHealthStatusBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (mental_health_status.empty()) {
        renderRoundedRect(renderer, mentalHealthStatusBox_X, mentalHealthStatusBox_Y - scrollOffsetY, mentalHealthStatusBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(mental_health_status.c_str(), mentalHealthStatusBox_X + offset, mentalHealthStatusBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}

// Sleep Patterns
if (enteringSleepPatterns && !sleep_patterns.empty()) {
    renderText(sleep_patterns.c_str(), sleepPatternsBox_X + offset, sleepPatternsBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (sleep_patterns.empty()) {
        renderRoundedRect(renderer, sleepPatternsBox_X, sleepPatternsBox_Y - scrollOffsetY, sleepPatternsBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(sleep_patterns.c_str(), sleepPatternsBox_X + offset, sleepPatternsBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}


 
 }

    if (showCognitiveReportsDetails) {

        
renderText(personalInfoText, xPersonalInfo, yPersonalInfo6 - scrollOffsetY, white, NimbusRomFont, renderer);

// Social Media Profiles
 renderText(socialMediaText, xSocialMedia, ySocialMedia6- scrollOffsetY, white, NimbusRomFont, renderer);

// Contact Information
 renderText(contactInfoText, xContactInfo, yContactInfo6- scrollOffsetY, white, NimbusRomFont, renderer);

// Education Information
 renderText(educationInfoText, xEducationInfo, yEducationInfo6- scrollOffsetY, white, NimbusRomFont, renderer);

// Health and Wellness
 renderText(healthWellnessText, xHealthWellness, yHealthWellness6- scrollOffsetY, white, NimbusRomFont, renderer);


// Custom Content
 renderText(customContentText, xCustomContent, yCustomContent6- scrollOffsetY, white, NimbusRomFont, renderer);

// Emergency Contact Information
 renderText(emergencyContactText, xEmergencyContact, yEmergencyContact6- scrollOffsetY, white, NimbusRomFont, renderer);

// Legal and Consent
 renderText(legalConsentText, xLegalConsent, yLegalConsent6- scrollOffsetY, white, NimbusRomFont, renderer);
    // showcognitiveReportsText6= true;    

showcognitiveReportsText6=true;
renderText("Neuropsychological Evaluation", xNeuropsychologicalAssessments, yNeuropsychologicalAssessments- scrollOffsetY, white, NunitoFont, renderer);
renderText("Electroencephalography", xEeg, yEeg- scrollOffsetY, white, NunitoFont, renderer);
renderText("Quantitative Electroencephalography", xQeeg, yQeeg- scrollOffsetY, white, NunitoFont, renderer);
renderText("Functional Magnetic Resonance Imaging", xFmri, yFmri- scrollOffsetY, white, NunitoFont, renderer);
renderText("Magnetic Resonance Imaging", xMri, yMri- scrollOffsetY, white, NunitoFont, renderer);
renderText("Computed Tomography", xCtScan, yCtScan- scrollOffsetY, white, NunitoFont, renderer);
renderText("Evoked Potentials", xEvokedPotentials, yEvokedPotentials- scrollOffsetY, white, NunitoFont, renderer);
renderText("Polysomnography", xSleepStudies, ySleepStudies- scrollOffsetY, white, NunitoFont, renderer);
renderText("Cerebrospinal Fluid Analysis", xCsfAnalysis, yCsfAnalysis- scrollOffsetY, white, NunitoFont, renderer);


renderRoundedRect(renderer, neuropsychologicalAssessmentsBox_X, neuropsychologicalAssessmentsBox_Y- scrollOffsetY, uploadboxwidth+100, uploadboxheight-8, radius, white);
renderRoundedRect(renderer, eegBox_X, eegBox_Y- scrollOffsetY, uploadboxwidth+100, uploadboxheight-8, radius, white);
renderRoundedRect(renderer, qeegBox_X, qeegBox_Y- scrollOffsetY, uploadboxwidth+100, uploadboxheight-8, radius, white);
renderRoundedRect(renderer, fmriBox_X, fmriBox_Y- scrollOffsetY, uploadboxwidth+100, uploadboxheight-8, radius, white);
renderRoundedRect(renderer, mriBox_X, mriBox_Y- scrollOffsetY, uploadboxwidth+100, uploadboxheight-8, radius, white);
renderRoundedRect(renderer, ctScanBox_X, ctScanBox_Y- scrollOffsetY, uploadboxwidth+100, uploadboxheight-8, radius, white);
renderRoundedRect(renderer, evokedPotentialsBox_X, evokedPotentialsBox_Y- scrollOffsetY, uploadboxwidth+100, uploadboxheight-8, radius, white);
renderRoundedRect(renderer, sleepStudiesBox_X, sleepStudiesBox_Y- scrollOffsetY, uploadboxwidth+100, uploadboxheight-8, radius, white);
renderRoundedRect(renderer, csfAnalysisBox_X, csfAnalysisBox_Y- scrollOffsetY, uploadboxwidth+100, uploadboxheight-8, radius, white);
}

    if (showCustomContentDetails) {
        
renderText(personalInfoText, xPersonalInfo, yPersonalInfo7 - scrollOffsetY, white, NimbusRomFont, renderer);

// Social Media Profiles
 renderText(socialMediaText, xSocialMedia, ySocialMedia7- scrollOffsetY, white, NimbusRomFont, renderer);

// Contact Information
 renderText(contactInfoText, xContactInfo, yContactInfo7- scrollOffsetY, white, NimbusRomFont, renderer);

// Education Information
 renderText(educationInfoText, xEducationInfo, yEducationInfo7- scrollOffsetY, white, NimbusRomFont, renderer);

// Health and Wellness
 renderText(healthWellnessText, xHealthWellness, yHealthWellness7- scrollOffsetY, white, NimbusRomFont, renderer);

// Cognitive Reports
 renderText(cognitiveReportsText, xCognitiveReports, yCognitiveReports7- scrollOffsetY, white, NimbusRomFont, renderer);


// Emergency Contact Information
 renderText(emergencyContactText, xEmergencyContact, yEmergencyContact7- scrollOffsetY, white, NimbusRomFont, renderer);

// Legal and Consent
 renderText(legalConsentText, xLegalConsent, yLegalConsent7- scrollOffsetY, white, NimbusRomFont, renderer);
    // showcustomContentText7=true;    

showcustomContentText7=true;
renderText("Text", xTextContent, yTextContent- scrollOffsetY, white, NunitoFont, renderer);
renderText("PDFs", xPdfs, yPdfs- scrollOffsetY, white, NunitoFont, renderer);
renderText("Images", xImages, yImages- scrollOffsetY, white, NunitoFont, renderer);
renderText("Videos", xVideos, yVideos- scrollOffsetY, white, NunitoFont, renderer);
renderText( "Audio", xAudio, yAudio- scrollOffsetY, white, NunitoFont, renderer);
renderText("Spreadsheets", xSpreadsheets, ySpreadsheets- scrollOffsetY, white, NunitoFont, renderer);
renderText("Presentations", xPresentations, yPresentations- scrollOffsetY, white, NunitoFont, renderer);
renderText("Code", xCode, yCode- scrollOffsetY, white, NunitoFont, renderer);
renderText( "3D Models", xModels, yModels- scrollOffsetY, white, NunitoFont, renderer);
renderText( "E-books" , xEbooks, yEbooks- scrollOffsetY, white, NunitoFont, renderer);
renderRoundedRect(renderer, textContentBox_X, textContentBox_Y- scrollOffsetY, uploadboxwidth, uploadboxheight, radius, white);
renderRoundedRect(renderer, pdfsBox_X, pdfsBox_Y- scrollOffsetY, uploadboxwidth, uploadboxheight, radius, white);
renderRoundedRect(renderer, imagesBox_X, imagesBox_Y- scrollOffsetY, uploadboxwidth, uploadboxheight, radius, white);
renderRoundedRect(renderer, videosBox_X, videosBox_Y- scrollOffsetY, uploadboxwidth, uploadboxheight, radius, white);
renderRoundedRect(renderer, audioBox_X, audioBox_Y- scrollOffsetY, uploadboxwidth, uploadboxheight, radius, white);
renderRoundedRect(renderer, spreadsheetsBox_X, spreadsheetsBox_Y- scrollOffsetY, uploadboxwidth, uploadboxheight, radius, white);
renderRoundedRect(renderer, presentationsBox_X, presentationsBox_Y- scrollOffsetY,uploadboxwidth, uploadboxheight, radius, white);
renderRoundedRect(renderer, codeBox_X, codeBox_Y- scrollOffsetY, uploadboxwidth, uploadboxheight, radius, white);
renderRoundedRect(renderer, modelsBox_X, modelsBox_Y- scrollOffsetY, uploadboxwidth, uploadboxheight, radius, white);
renderRoundedRect(renderer, ebooksBox_X, ebooksBox_Y- scrollOffsetY, uploadboxwidth, uploadboxheight, radius, white);

 }

    if (showEmergencyContactDetails) {
        
renderText(personalInfoText, xPersonalInfo, yPersonalInfo8 - scrollOffsetY, white, NimbusRomFont, renderer);

// Social Media Profiles
 renderText(socialMediaText, xSocialMedia, ySocialMedia8- scrollOffsetY, white, NimbusRomFont, renderer);

// Contact Information
 renderText(contactInfoText, xContactInfo, yContactInfo8- scrollOffsetY, white, NimbusRomFont, renderer);

// Education Information
 renderText(educationInfoText, xEducationInfo, yEducationInfo8- scrollOffsetY, white, NimbusRomFont, renderer);

// Health and Wellness
 renderText(healthWellnessText, xHealthWellness, yHealthWellness8- scrollOffsetY, white, NimbusRomFont, renderer);

// Cognitive Reports
 renderText(cognitiveReportsText, xCognitiveReports, yCognitiveReports8- scrollOffsetY, white, NimbusRomFont, renderer);

// Custom Content
 renderText(customContentText, xCustomContent, yCustomContent8- scrollOffsetY, white, NimbusRomFont, renderer);


// Legal and Consent
 renderText(legalConsentText, xLegalConsent, yLegalConsent8- scrollOffsetY, white, NimbusRomFont, renderer);
        // showemergencyContactText8= true;

showemergencyContactText8=true;
renderText("Primary Contact Name", xPrimaryContactName, yPrimaryContactName- scrollOffsetY, white, NunitoFont, renderer);
renderText( "Relationship", xRelationship, yRelationship- scrollOffsetY, white, NunitoFont, renderer);
renderText("Phone Number", xEmergencyPhoneNumber, yEmergencyPhoneNumber- scrollOffsetY, white, NunitoFont, renderer);


renderRoundedRect(renderer, primaryContactNameBox_X, primaryContactNameBox_Y- scrollOffsetY, primaryContactNameBox_WIDTH, inputBoxHeight, radius, white);
renderRoundedRect(renderer, relationshipBox_X, relationshipBox_Y- scrollOffsetY, relationshipBox_WIDTH, inputBoxHeight, radius, white);
renderRoundedRect(renderer, emergencyPhoneNumberBox_X, emergencyPhoneNumberBox_Y- scrollOffsetY, emergencyPhoneNumberBox_WIDTH, inputBoxHeight, radius, white);

// Primary Contact Name
if (enteringPrimaryContactName && !primary_contact_name.empty()) {
    renderText(primary_contact_name.c_str(), primaryContactNameBox_X + offset, primaryContactNameBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (primary_contact_name.empty()) {
        renderRoundedRect(renderer, primaryContactNameBox_X, primaryContactNameBox_Y - scrollOffsetY, primaryContactNameBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(primary_contact_name.c_str(), primaryContactNameBox_X + offset, primaryContactNameBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}

// Relationship
if (enteringRelationship && !relationship.empty()) {
    renderText(relationship.c_str(), relationshipBox_X + offset, relationshipBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (relationship.empty()) {
        renderRoundedRect(renderer, relationshipBox_X, relationshipBox_Y - scrollOffsetY, relationshipBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(relationship.c_str(), relationshipBox_X + offset, relationshipBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}

// Emergency Phone Number
if (enteringEmergencyPhoneNumber && !emergency_phone_number.empty()) {
    renderText(emergency_phone_number.c_str(), emergencyPhoneNumberBox_X + offset, emergencyPhoneNumberBox_Y - scrollOffsetY, black, NunitoFont, renderer);
} else {
    if (emergency_phone_number.empty()) {
        renderRoundedRect(renderer, emergencyPhoneNumberBox_X, emergencyPhoneNumberBox_Y - scrollOffsetY, emergencyPhoneNumberBox_WIDTH, inputBoxHeight, radius, white);
    } else {
        renderText(emergency_phone_number.c_str(), emergencyPhoneNumberBox_X + offset, emergencyPhoneNumberBox_Y - scrollOffsetY, black, NunitoFont, renderer);
    }
}

}



    if (showLegalConsentDetails) {
        
renderText(personalInfoText, xPersonalInfo, yPersonalInfo9 - scrollOffsetY, white, NimbusRomFont, renderer);

// Social Media Profiles
 renderText(socialMediaText, xSocialMedia, ySocialMedia9- scrollOffsetY, white, NimbusRomFont, renderer);

// Contact Information
 renderText(contactInfoText, xContactInfo, yContactInfo9- scrollOffsetY, white, NimbusRomFont, renderer);

// Education Information
 renderText(educationInfoText, xEducationInfo, yEducationInfo9- scrollOffsetY, white, NimbusRomFont, renderer);

// Health and Wellness
 renderText(healthWellnessText, xHealthWellness, yHealthWellness9- scrollOffsetY, white, NimbusRomFont, renderer);

// Cognitive Reports
 renderText(cognitiveReportsText, xCognitiveReports, yCognitiveReports9- scrollOffsetY, white, NimbusRomFont, renderer);

// Custom Content
 renderText(customContentText, xCustomContent, yCustomContent9- scrollOffsetY, white, NimbusRomFont, renderer);

// Emergency Contact Information
 renderText(emergencyContactText, xEmergencyContact, yEmergencyContact9- scrollOffsetY, white, NimbusRomFont, renderer);

        // showlegalConsentText9= true;
      
showlegalConsentText9=true;

        renderTextUnderlined("Consent Forms", xConsentForms, yConsentForms - scrollOffsetY, skyblue, NunitoFont, renderer);
        renderTextUnderlined("License Agreements", xLicenseAgreements, yLicenseAgreements - scrollOffsetY, skyblue, NunitoFont, renderer);
        renderTextUnderlined("Terms of Service", xTermsOfService, yTermsOfService - scrollOffsetY, skyblue, NunitoFont, renderer);

        SDL_Rect checkbox1 = {consentFormsBox_X, consentFormsBox_Y - scrollOffsetY, checkboxSize2, checkboxSize2};
        SDL_SetRenderDrawColor(renderer, 255, 255, 255, 255);
        SDL_RenderFillRect(renderer, &checkbox1);

        SDL_Rect checkbox2 = {licenseAgreementsBox_X, licenseAgreementsBox_Y - scrollOffsetY, checkboxSize2, checkboxSize2};
        SDL_SetRenderDrawColor(renderer, 255, 255, 255, 255);
        SDL_RenderFillRect(renderer, &checkbox2);

        SDL_Rect checkbox3 = {termsOfServiceBox_X, termsOfServiceBox_Y - scrollOffsetY, checkboxSize2, checkboxSize2};
        SDL_SetRenderDrawColor(renderer, 255, 255, 255, 255);
        SDL_RenderFillRect(renderer, &checkbox3);

        // Render checkmark if checkbox is checked
        if (isCheckbox1Checked)
        {
            SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);

            // Draw the left part of the tick
            SDL_RenderDrawLine(renderer, tickStartX1, tickStartY1 - scrollOffsetY, tickMiddleX1, tickMiddleY1 - scrollOffsetY);

            // Draw the right part of the tick
            SDL_RenderDrawLine(renderer, tickMiddleX1, tickMiddleY1 - scrollOffsetY, tickEndX1, tickEndY1 - scrollOffsetY);

}


 // Render checkmark if checkbox is checked
if (isCheckbox2Checked) {
    SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);

    // Draw the tick mark lines
    SDL_RenderDrawLine(renderer, tickStartX2, tickStartY2- scrollOffsetY, tickMiddleX2, tickMiddleY2- scrollOffsetY);
    SDL_RenderDrawLine(renderer, tickMiddleX2, tickMiddleY2- scrollOffsetY, tickEndX2, tickEndY2- scrollOffsetY);
}


 // Render checkmark if checkbox is checked
if (isCheckbox3Checked) {
    SDL_SetRenderDrawColor(renderer, 0, 0, 0, 255);

    // Draw the tick mark lines
    SDL_RenderDrawLine(renderer, tickStartX3, tickStartY3- scrollOffsetY, tickMiddleX3, tickMiddleY3- scrollOffsetY);
    SDL_RenderDrawLine(renderer, tickMiddleX3, tickMiddleY3- scrollOffsetY, tickEndX3, tickEndY3- scrollOffsetY);
}
    
    
    }



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
    SettingsScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* NunitoFont)
        : NavigationMenu(window, renderer, NunitoFont) {
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
    CognitiveStatsScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* NunitoFont)
        : NavigationMenu(window, renderer, NunitoFont) {
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
    DataStatsScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* NunitoFont)
        : NavigationMenu(window, renderer, NunitoFont) {
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
    TargetsScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* NunitoFont)
        : NavigationMenu(window, renderer, NunitoFont) {
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
    SystemHealthScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* NunitoFont)
        : NavigationMenu(window, renderer, NunitoFont) {
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


class ConsentFormsScreenState : public State {
private:
     SDL_Color white = { 255, 255, 255, 255 };
    SDL_Color grey = { 100, 100, 100, 255 };
    SDL_Color black = { 0, 0, 0, 255 };
    SDL_Color darkgreen = { 0, 50, 0, 255  }; 
    SDL_Color maroon = { 128, 0, 0, 255 };
 
public:
   ConsentFormsScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* NunitoFont)
        : State(window, renderer, NunitoFont){
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

class LicenseAgreementsScreenState : public State {
private:
     SDL_Color white = { 255, 255, 255, 255 };
    SDL_Color grey = { 100, 100, 100, 255 };
    SDL_Color black = { 0, 0, 0, 255 };
    SDL_Color darkgreen = { 0, 50, 0, 255  }; 
    SDL_Color maroon = { 128, 0, 0, 255 };
 
public:
   LicenseAgreementsScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* NunitoFont)
        : State(window, renderer, NunitoFont){
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

class TermsOfServiceScreenState : public State {
private:
     SDL_Color white = { 255, 255, 255, 255 };
    SDL_Color grey = { 100, 100, 100, 255 };
    SDL_Color black = { 0, 0, 0, 255 };
    SDL_Color darkgreen = { 0, 50, 0, 255  }; 
    SDL_Color maroon = { 128, 0, 0, 255 };
 
public:
   TermsOfServiceScreenState(SDL_Window* window, SDL_Renderer* renderer, TTF_Font* NunitoFont)
        : State(window, renderer, NunitoFont){
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
    
    {PROFILE_UPDATE_SCREEN, {50, 50, 50, 255}},    // Dark Grey
    {SETTINGS_SCREEN, {50, 50, 50, 255}},    // Dark Grey
    {COGNITIVE_STATS_SCREEN, {50, 50, 50, 255}},    // Dark Grey
    {DATA_STATS_SCREEN, {50, 50, 50, 255}},    // Dark Grey
    {TARGETS_SCREEN, {50, 50, 50, 255}},    // Dark Grey
    {SYSTEM_HEALTH_SCREEN, {50, 50, 50, 255}},    // Dark Greyz
    {CONSENT_FORMS_SCREEN  , {50, 50, 50, 255}},    // Dark Greyz
    {LICENSE_AGREEMENTS_SCREEN      , {50, 50, 50, 255}},    // Dark Greyz
    {TERMS_OF_SERVICE_SCREEN, {50, 50, 50, 255}},    // Dark Greyz
    
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
            currentStateInstance = std::make_unique<SplashScreenState>(window, renderer, NunitoFont);
            break;
        case LOGIN_SCREEN:
            currentStateInstance = std::make_unique<LoginScreenState>(window, renderer, NunitoFont);
            break;
        case SIGNUP_SCREEN:
            currentStateInstance = std::make_unique<SignupScreenState>(window, renderer, NunitoFont);
            break;
        case MAIN_DASHBOARD:
            currentStateInstance = std::make_unique<MainDashboardScreenState>(window, renderer, NunitoFont);
            break; 

         case F_VERIFICATION_SCREEN:
            currentStateInstance = std::make_unique<FVerificationScreenState>(window, renderer, NunitoFont);
            break;
        case S_VERIFICATION_SCREEN:
            currentStateInstance = std::make_unique<SVerificationScreenState>(window, renderer, NunitoFont);
            break;
         
        case PASSWORD_RESET_SCREEN:
            currentStateInstance = std::make_unique<PasswordResetScreenState>(window, renderer, NunitoFont);
            break; 
        case HELP_SCREEN:
            currentStateInstance = std::make_unique<HelpScreenState>(window, renderer, NunitoFont);
            break;
             case PROFILE_SCREEN:
            currentStateInstance = std::make_unique<ProfileScreenState>(window, renderer, NunitoFont);
            break;
            case PROFILE_UPDATE_SCREEN:
    currentStateInstance = std::make_unique<ProfileUpdateScreenState>(window, renderer, NunitoFont, NimbusRomFont, currentUser.get(), db);
    break;

             case SETTINGS_SCREEN:
            currentStateInstance = std::make_unique<SettingsScreenState>(window, renderer, NunitoFont);
            break;
             case COGNITIVE_STATS_SCREEN:
            currentStateInstance = std::make_unique<CognitiveStatsScreenState>(window, renderer, NunitoFont);
            break;
             case DATA_STATS_SCREEN:
            currentStateInstance = std::make_unique<DataStatsScreenState>(window, renderer, NunitoFont);
            break;
             case TARGETS_SCREEN:
            currentStateInstance = std::make_unique<TargetsScreenState>(window, renderer, NunitoFont);
            break;
             case SYSTEM_HEALTH_SCREEN:
            currentStateInstance = std::make_unique<SystemHealthScreenState>(window, renderer, NunitoFont);
            break;
            case CONSENT_FORMS_SCREEN:
            currentStateInstance = std::make_unique<ConsentFormsScreenState>(window, renderer, NunitoFont);
            break;
             case LICENSE_AGREEMENTS_SCREEN:
            currentStateInstance = std::make_unique<LicenseAgreementsScreenState>(window, renderer, NunitoFont);
            break;
             case TERMS_OF_SERVICE_SCREEN:
            currentStateInstance = std::make_unique<TermsOfServiceScreenState>(window, renderer, NunitoFont);
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
    NunitoFont = TTF_OpenFont("C:/NEW/assets/Nunito-Regular.ttf", 18);
    if (!NunitoFont) {
        std::cerr << "Failed to load font: " << TTF_GetError() << std::endl;
        SDL_DestroyRenderer(renderer);
        SDL_DestroyWindow(window);
        TTF_Quit();
        SDL_Quit();
        return -1;
    }

     // Load bold nunito font
    NimbusRomFont = TTF_OpenFont("C:/NEW/assets/NimbusRomNo9L-Reg.otf", 24);
    if (!NimbusRomFont) {
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

    TTF_CloseFont(NunitoFont);
    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    TTF_Quit();
    SDL_Quit();

    return 0;
}

// sub kuch low quality lag rha hy 
//2. sendinblue authentication ka masla

//4. database sqlite sey change kr k kuch aur krna hy 




 ///////////////
            
        //      else if (event.type == SDL_TEXTINPUT) {
        //     if (enteringUsername && username.size() < 15) {
        //         username += event.text.text;
        //     } else if (!enteringUsername && password.size() < 15) {
        //         password += event.text.text;
        //     }
        // }

//may be you should limit it becasue liimtless hoa tu attack k  chances hn


 
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

//for search elements in the main menu of  // enter key would search for that data and bring that up but that would be implemented later on 
//next i need to handle event clicks for different data types and that should be connected to some kind of fillter system to bring only that data for me 


//in the main menu i need to render the bellicon



// jab yeah sub kr lo tu phir wo dusri library waly masly dekho wahan files upload kr k save karo database mn 
// aur phir us k bad database hi badl dalo

//  finger touch event ya enter aur backspace evetn yeah sub bhi abhi set karny hn
// aur us k bad cursor ka bhi kuch kar lo
// us k bad profile photo ko dekho 




//list of errors


/*
ek tu authentication ka masla(for this i need some one's help i know i can't do this alone)
dusra profile update screen ka masla(yep i need someone or i should take a little break andd try this some other time )


teesra database change krni zarori hhy bht pehly wo kr lo   %%%%%%%%%%%# target 1%%%%%%%%%%%



phir main dashboard pr algorithms lagao us data ko search kr k presetn krny waghera k ley and so on 
(is sey pehly database change karna zarori hy aur librareis laga kr data add karna bhi pry ga aur us custom content ka bhi tu kuch krna hy pehly)
           %%%%%%%   # target 2 %%%%%%

phir bus phir us k bad baki sari screens mn data dalo
and move on
%%%%%%%%%%%%      # target 3 %%%%%%%%%%%%%


meanwhile agr koi marketing expert ya two factor authentication wala banda mil gya tu  pehla problem discuss kr lein gy 

 aur agr koi i dotn know backend yaend developer mil gya tu 



*/
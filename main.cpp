#include <iostream>
#include <regex>
#include <fmt/core.h>
#include <fstream>
#include <sstream>
#include <map>
#include <filesystem>

/*
 * Define:
 * 1. Supported formats and their extensions
 * 2. Signatures' sizes
 * 3. Signatures
 * 4. Other constants
 */
#define EXT_PPM ".ppm" // File extension for PPM format
#define EXT_BMP ".bmp" // File extension for BMP format

#define PPM_SIG_SZ 2 // Size of PPM signatures
const uint8_t ppmSign1[PPM_SIG_SZ] = {0x50, 0x33}; // Signature for P3 format
const uint8_t ppmSign2[PPM_SIG_SZ] = {0x50, 0x36}; // Signature for P6 format

#define BMP_SIG_SZ 2 // Size of BMP signature
const uint8_t bmpSign[BMP_SIG_SZ] = {0x42, 0x4D}; // Signature for BMP format

#define BITS_PER_CHAR 8 // Number of bits per character

namespace fs = std::filesystem; // Alias for the filesystem namespace


/*
 * @brief PJC namespace contains all 'support' functions not callable via flags
*/
namespace pjc {
    /*
     * @brief pjc::image namespace contains 'support' functions for interacting with image
     */
    namespace image {
        /*
         * @brief Enumerates endianness options for future format support
         *        to convert bytes in the correct order.
         *
         *    For example:
         *      - BMP: Little Endian
         *      - PNG: Big Endian
         */
        enum class Endianness {
            LittleEndian,
            BigEndian
        };

        /*
         * @brief Struct for storing PPM header information.
         */
        struct PPMInfo {
            uint32_t width;         // Width of the image
            uint32_t height;        // Height of the image
            uint32_t maxColorValue; // Maximum color value
            int offsetToData;       // Offset to the start of image data
        };

        /*
         * @brief Changes the extension of a file path to lowercase.
         *
         * @param file_path Path to a file
         * @return Lowercase string representing the file extension.
         */
        std::string getFileExtension(const fs::path& file_path) {
            std::string extenstion = file_path.extension().string();
            std::transform(extenstion.begin(), extenstion.end(), extenstion.begin(), ::tolower);
            return extenstion;
        }

        /*
         * @brief Reads bytes from a file at a specified offset.
         *        Panics if anything goes wrong.
         *
         * @param file_path Path to a file
         * @param offset    Offset from the start of the file
         * @param dest      Pointer to the destination for read bytes
         * @param size      Number of bytes to read
         */
        void readBytesOrPanic (const fs::path& file_path, uint32_t offset, char* dest, uint32_t size) {
            std::ifstream file(file_path, std::ios::binary);

            if (!file.is_open()) {
                std::cerr << "Failed to open file: " << file_path << std::endl;
                return;
            }

            file.seekg(offset, std::ios::beg);
            if (!file) {
                std::cerr << "Failed to seek to position " + std::to_string(offset) +
                             " in file: " + file_path.string();
                return;
            }

            file.read(dest, size);
            if (!file) {
                if (file.eof()) {
                    std::cerr << "Unexpected end of file: " + file_path.string();
                    return;
                }
                else{
                    std::cerr << "Failed to read from file: " + file_path.string();
                    return;
                }
            }
        }

        /*
         * @brief Reads PPM header information and returns it.
         *
         *    Steps:
         *    1. Opens the PPM file
         *    2. Checks the correctness of the signature
         *    3. Skips comments if there are any
         *    4. Saves width, height, max color value, and offset to data
         *
         * @param file_path Path to a PPM file
         * @return PPMInfo struct containing header information
         */
        PPMInfo readPPMHeader(const std::string& file_path) {
            PPMInfo info = {0, 0, 0, -1};
            std::ifstream file(file_path, std::ios::binary);

            if (!file.is_open()) {
                std::cerr << "Failed to open file: " << file_path << std::endl;
                return info;
            }

            std::string format;
            file >> format;

            if (format != "P3" and format != "P6") {
                std::cerr << "Unsupported PPM format: " << format << std::endl;
                return info;
            }

            // Skip comments in the header
            char chr;
            file >> std::ws;
            while (file.peek() == '#'){
                // Ignore characters until newline character is encountered
                file.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            }

            file >> info.width >> info.height >> info.maxColorValue;

            // Read one more character (usually '\n') after header information
            // This ensures the file pointer is correctly positioned at the start of the image data
            file.get(chr);
            info.offsetToData = file.tellg();

            file.close();
            return info;
        }

        /*
         * @brief Converts bytes to uint32_t considering endianness.
         *
         * @param bytes      Pointer to the bytes
         * @param size       Number of bytes
         * @param endianness Endianness of the bytes
         * @return Converted uint32_t value
         */
        uint32_t bytesToUint32(const char *bytes, size_t size, Endianness endianness) {
            uint32_t value = 0;
            for (size_t i = 0; i < size; ++i) {
                if (endianness == Endianness::LittleEndian)
                    value |= static_cast<uint32_t>(static_cast<unsigned char>(bytes[i])) << (i * 8);
                else if (endianness == Endianness::BigEndian)
                    value |= static_cast<uint32_t>(static_cast<unsigned char>(bytes[i])) << ((size - 1 - i) * 8);
            }
            return value;
        }

        /*
         * @brief Get offset to the start of pixel data
         *
         * @param file_path Path to a file
         * @return int offset to the start of pixel data
         */
        int getOffsetToData(const fs::path& file_path) {
            int offsetToData = -1;
            std::string extension = pjc::image::getFileExtension(file_path);

            if (extension == EXT_PPM) {
                pjc::image::PPMInfo info = pjc::image::readPPMHeader(file_path);
                offsetToData = info.offsetToData;
            }
            else if (extension == EXT_BMP) {
                char offset[4];
                pjc::image::readBytesOrPanic(file_path, 10, offset, sizeof(offset));
                offsetToData = bytesToUint32(offset, sizeof(offset), pjc::image::Endianness::LittleEndian);
            }

            return offsetToData;
        }

        /*
         * @brief Counts the number of characters that can be encoded in the image.
         *
         *    Steps:
         *    1. Calculate the size of the pixel data by subtracting the header data size from the file size.
         *    2. Calculate the number of characters that can be encoded by dividing the pixel data size by 8.
         *    3. Reserve 8 bytes for the zero character (end of message signal) by subtracting 1 character.
         *
         * @param file_path Path to the image file
         * @return Number of characters that can be encoded
         */
        size_t countEncodableChars(const fs::path& file_path) {
            size_t encodableCharCount = 0;

            int offsetToData = getOffsetToData(file_path);
            encodableCharCount = (file_size(file_path) - offsetToData) / BITS_PER_CHAR - 1;

            return encodableCharCount;
        }
    }

    /*
     * @brief pjc::text namespace contains 'support' functions for interacting with text
     */
    namespace text {
        /*
         * @brief Creates and returns a map with all supported characters,
         *        so that characters with 2+ bytes length are encoded in 1 byte.
         *
         *        The map is static, so it is stored in memory till the end of the program's execution.
         *
         * Important remarks, using this approach for encoding:
         * Advantages:
         * 1. We populate the map in the desired order, making it harder for others to decrypt messages without the map.
         * 2. We can change the order of characters whenever necessary to ensure message security.
         *
         * Disadvantages:
         * 1. Only 255 characters can be encoded using one byte.
         * (It is possible to increase by adding more bits to encode one character BITS_PER_CHAR)
         * (Small adjustments might be needed)
         *
         * @return map
         */
        std::map<std::string, std::uint8_t> getSupportedChars() {
            static std::map<std::string, std::uint8_t> map;

            if (not map.empty())
                return map;

            // Enable UTF-8 encoding
            std::locale::global(std::locale(""));

            // 0 is reserved for '\0'
            std::uint8_t value = 1;

            map[std::string(1, ' ')] = value++;

            for (char d = '0'; d <= '9'; ++d)
                map[std::string(1, d)] = value++;

            for (char c = 'A'; c <= 'Z'; ++c)
                map[std::string(1, c)] = value++;

            for (char c = 'a'; c <= 'z'; ++c)
                map[std::string(1, c)] = value++;

            const char punctuation[] = {
                '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
                ':', ';', '<', '=', '>', '?', '@',
                '[', '\\', ']', '^', '_', '`',
                '{', '|', '}', '~'
            };
            for (char c : punctuation)
                map[std::string(1, c)] = value++;

            // Non-ASCII
            std::string nonASCII =
                    "ąćęłńóśżź"
                    "ĄĆĘŁŃÓŚŻŹ"
                    "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
                    "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
                    "ґєії"
                    "ҐЄІЇ";

            for (size_t i = 0; i < nonASCII.size(); i += 2)
                map[std::string(reinterpret_cast<const char*>(&nonASCII[i]), 2)] = value++;

            return map;
        }

        /*
        * @brief Checks if a character is ASCII
        *
        * @return true if ASCII, false otherwise
        */
        bool isASCII(char c) {
            return static_cast<unsigned char>(c) <= 127;
        }

        /*
         * @brief Counts the number of characters in a message
         *
         *    Using iterators, we can properly count the number of characters (not bytes) in the message.
         *    Non-ASCII characters take 2 bytes, so we use ++it to move one byte forward.
         *
         * @return size_t
         */
        size_t charsInMessage(const std::string& message) {
            size_t counter = 0;
            for (auto it = message.begin(); it != message.end(); ++it) {
                if (not isASCII(*it))
                    ++it;
                counter++;
            }
            return counter;
        }

        /*
         * @brief Finds a key by its value in the map
         *
         * @return string
         */
        std::string findKeyByValue(const std::map<std::string, std::uint8_t>& map, std::uint8_t value) {
            for (const auto& pair : map) {
                if (pair.second == value)
                    return pair.first;
            }
            return "";
        }

        /*
         * @brief Encodes characters from the message using the map
         *
         * @return vector of values
         */
        std::vector<std::uint8_t> encodeMessage(const std::string& message) {
            const auto& map = getSupportedChars();
            std::vector<std::uint8_t> nums;

            for (auto it = message.begin(); it != message.end(); ++it) {
                std::string key;
                if (isASCII(*it)) {
                    key = std::string(it, it + 1);
                } else {
                    key = std::string(it, it + 2);
                    ++it;
                }
                nums.push_back(map.at(key));
            }
            return nums;
        }

        /*
         * @brief Decodes values from the vector using the map
         *
         * @return string message
         */
        std::string decodeMessage(const std::vector<std::uint8_t>& nums) {
            const auto& map = getSupportedChars();
            std::string message;

            for (const auto& num : nums) {
                std::string chr = findKeyByValue(map, num);
                message+=chr;
            }
            return message;
        }
    }

    /*
     * @brief pjc::failure namespace contains 'support' functions for checking:
     * 1. File Signature
     * 2. File path
     * 3. Message
     */
    namespace failure {

        /*
         * @brief Checks if the file signature is correct
         *
         *    Steps:
         *    1. Read bytes from a file
         *    2. Compare byte by byte
         *
         * @param file_path    Path to a file
         * @param sig_sz       Signature size
         * @param compare_with Pointer to signature to compare with
         *
         * @return true if the signature matches, false otherwise
         */
        bool isValidFileSignature(const fs::path& file_path, uint8_t sig_sz, const uint8_t *compare_with) {
            char sign[sig_sz];
            pjc::image::readBytesOrPanic(file_path, 0, sign, sig_sz);

            for (int i = 0; i < sig_sz; ++i)
                if (static_cast<unsigned char>(sign[i]) != compare_with[i])
                    return false;

            return true;
        }

        /*
         * @brief Checks if the file path is correct
         *
         * @param file_path Path to a file
         *
         * @return true if the file path is correct, false otherwise
         */
        bool isCorrectFilePath(const fs::path& file_path) {
            if (not fs::exists(file_path)) {
                std::cerr << ("File path does not exist.\n");
                return false;
            }

            if (fs::is_directory(file_path)) {
                std::cerr << ("File path is a directory.\n");
                return false;
            }

            if (not fs::is_regular_file(file_path)) {
                std::cerr << ("File path is not a regular file.\n");
                return false;
            }

            if ((fs::status(file_path).permissions() & fs::perms::owner_read) == fs::perms::none) {
                std::cerr << ("No permission to read the file.\n");
                return false;
            }

            if (fs::file_size(file_path) == 0) {
                std::cerr << ("File is empty.\n");
                return false;
            }

            if (file_path.string().length() > 260) {
                std::cerr << ("File path exceeds maximum length (260).\n");
                return false;
            }

            std::string extenstion = image::getFileExtension(file_path);
            if (extenstion != EXT_PPM and extenstion != EXT_BMP) {
                std::cerr << ("File extension is not supported.\nUse -h for help.\n");
                return false;
            }

            if (extenstion == EXT_PPM) {
                if (not (isValidFileSignature(file_path, PPM_SIG_SZ, ppmSign1) or
                         isValidFileSignature(file_path, PPM_SIG_SZ, ppmSign2))) {
                    std::cerr << ("File extension is not valid.\nFile might be corrupted.\n");
                    return false;
                }
            }
            else if (extenstion == EXT_BMP) {
                if (not isValidFileSignature(file_path, BMP_SIG_SZ, bmpSign)){
                    std::cerr << ("File extension is not valid.\nFile might be corrupted.\n");
                    return false;
                }
            }

            return true;
        }

        /*
         * @brief Checks if the message is correct:
         *
         *    1. Not empty
         *    2. All characters in the message are supported (present in the map)
         *
         * @param file_path Path to a file
         * @param message   Message to check
         *
         * @return true if the message is correct, false otherwise
         */
        bool isCorrectMessage(const fs::path& file_path, const std::string& message) {
            if (message.empty()) {
                std::cerr << "Your message is empty.\n";
                return false;
            }

            const auto& map = text::getSupportedChars();

            for (auto it = message.begin(); it != message.end(); ++it) {
                std::string key;
                if (text::isASCII(*it)) {
                    key = std::string(it, it+1);
                } else {
                    key = std::string(it, it+2);
                    ++it;
                }
                if (map.find(key) == map.end()) {
                    std::cerr << "Not all the chars are supported.\nUse -s to see supported ones.\n";
                    return false;
                }
            }

            return true;
        }
    }
}

/*
 * @brief Displays information about the file:
 * 1. Path
 * 2. Name
 * 3. File Extension
 * 4. Size in bytes
 * 5. Image Dimensions (width × height)
 * 6. Formatted Last Write Time to a file (yyyy-MM-dd hh:mm:ss)
 * 7. Formatted Permissions (rwxr--r--)
 *
 * @param file_path Path to a file
 */
void info(const fs::path& file_path) {
    // Getting canonical path, name, extension, and file size
    std::string canon_path = fs::canonical(file_path);
    std::string name       = file_path.stem();
    std::string extension  = file_path.extension();
    uintmax_t size         = fs::file_size(file_path);

    // Calculating dimensions based on file format
    std::pair<uint32_t,uint32_t> dimensions;

    std::string extenstion = pjc::image::getFileExtension(file_path);
    if (extenstion == EXT_PPM) {
        pjc::image::PPMInfo info = pjc::image::readPPMHeader(file_path);
        dimensions.first = info.width, dimensions.second = info.height;
    }
    else if (extenstion == EXT_BMP) {
        char width[4], height[4]; // width (offset 18), height (offset 22)
        pjc::image::readBytesOrPanic(file_path, 18, width, sizeof(width));
        dimensions.first = bytesToUint32(width, sizeof(width), pjc::image::Endianness::LittleEndian);
        pjc::image::readBytesOrPanic(file_path, 22, height, sizeof(height));
        dimensions.second = bytesToUint32(height, sizeof(height), pjc::image::Endianness::LittleEndian);
    }

    // Formatting last write time of the file
    /* Read Here:
    * https://en.cppreference.com/w/cpp/filesystem/last_write_time
    * https://en.cppreference.com/w/cpp/chrono/time_point
    */
    auto last_write = fs::last_write_time(file_path);
    auto time_since_epoch = last_write.time_since_epoch();
    std::chrono::system_clock::time_point tp {
            std::chrono::duration_cast<std::chrono::system_clock::duration>(time_since_epoch) };

    std::time_t c_time = std::chrono::system_clock::to_time_t(tp);
    std::tm local_time = *std::localtime(&c_time);

    std::ostringstream last_write_;
    last_write_ << std::put_time(&local_time, "%Y-%m-%d %H:%M:%S");

    // Formatting file permissions
    /* Read Here:
     * https://en.cppreference.com/w/cpp/filesystem/perms
     */
    using std::filesystem::perms;
    auto file_status = fs::status(file_path);
    auto file_perms = file_status.permissions();

    auto get_perm = [&](perms p, char c) {
        return (file_perms & p) == perms::none ? '-' : c;
    };

    std::string perms;
    perms += get_perm(perms::owner_read, 'r');
    perms += get_perm(perms::owner_write, 'w');
    perms += get_perm(perms::owner_exec, 'x');
    perms += get_perm(perms::group_read, 'r');
    perms += get_perm(perms::group_write, 'w');
    perms += get_perm(perms::group_exec, 'x');
    perms += get_perm(perms::others_read, 'r');
    perms += get_perm(perms::others_write, 'w');
    perms += get_perm(perms::others_exec, 'x');

    // Displaying output
    fmt::println(
        "=-=- Information Section -=-="
        "\nPath: {}"
        "\nName: {}"
        "\nExtension: {}"
        "\nSize: {} bytes"
        "\nDimensions: {}×{}"
        "\nLast write time: {}"
        "\nPermissions: {}\n"
        "=-=- End of Information Section -=-=",
        canon_path,
        name,
        extension,
        size,
        dimensions.first, dimensions.second,
        last_write_.str(),
        perms
    );
}

/*
 * @brief Embeds the specified message into image's pixel data
 *
 * Steps:
 * 1. Checks permissions to write to the file
 * 2. Checks if there are enough bytes to embed the specified message
 *
 * Start of encryption:
 * 1. Opens file in binary mode for reading and writing
 * 2. Converts characters from the message to numbers using the map
 * 3. Adds zero as an end-of-message signal for decryption
 *
 * 4. Calculates the offset to the start of pixel data
 * 5. Moves to the calculated offset from the beginning of the file
 *
 * 6. Converts the decimal value to a bitset
 * 7. Reads a byte from the file, changes the least significant bit (LSB) to the value from the bitset
 * 8. Writes the modified byte back to the file
 * 9. Repeats steps 6-8 for each value in the message
 *
 * @param file_path Path to a file
 * @param message   Message to embed
*/
void encrypt(const fs::path& file_path, const std::string& message) {
    if ((fs::status(file_path).permissions() & fs::perms::owner_write) == fs::perms::none) {
        std::cerr << ("No permission to write to the file.\n");
        return;
    }

    // Checks if enough bytes to embed the specified message
    size_t charsInMessage = pjc::text::charsInMessage(message);
    size_t encodableCharCount = pjc::image::countEncodableChars(file_path);
    if (charsInMessage > encodableCharCount) {
        std::cerr << "The message is too long.\nUse -c to check.\n";
        return;
    }

    // Start of encryption
    std::fstream file(file_path, std::ios::binary | std::ios::in | std::ios::out);
    auto valsToEncrypt = pjc::text::encodeMessage(message);
    valsToEncrypt.push_back(0); // (end of message signal)

    int offsetToData = pjc::image::getOffsetToData(file_path);
    file.seekg(offsetToData, std::ios::beg);

    // Embed message into the image's pixel data
    for (uint8_t value : valsToEncrypt) {
        std::bitset<BITS_PER_CHAR> binVal(value);

        // Modify LSB of 8 consecutive bytes
        for (int i = BITS_PER_CHAR - 1; i >= 0; --i) {
            char byte;
            file.read(&byte, 1);

            // Set LSB to the current bit of the binary value
            byte = (byte & 0xFE) | binVal[i];

            // Synchronize write position
            file.seekp(file.tellg() - std::streampos(1));
            file.write(&byte, 1);
        }
    }

    fmt::println("Encryption done.");
}

/*
 * @brief Opens the image and extracts the embedded message
 *
 * Steps:
 * 1. Opens the file in binary mode for reading
 * 2. Declares a vector to store decoded values
 *
 * 3. Calculates the offset to the start of pixel data
 * 4. Moves to the calculated offset from the beginning of the file
 *
 * 5. Reads bytes and extracts the least significant bit (LSB), groups by 8
 * 6. Casts the decrypted byte to uint8_t
 * 7. If the decoded value is 0, no more characters to decrypt, stop decrypting
 * 8. If the value is not zero, adds it to the vector
 *
 * 9. Converts numbers from the vector to characters from the map
 * 10. Prints the decrypted message
 *
 * @param file_path Path to a file
*/
void decrypt(const fs::path& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    std::vector<std::uint8_t> decodedValues;

    int offsetToData = pjc::image::getOffsetToData(file_path);
    file.seekg(offsetToData, std::ios::beg);

    bool endOfFile = false;
    while (not endOfFile) {
        std::bitset<BITS_PER_CHAR> decryptedByte;

        // Extract LSB from 8 consecutive bytes
        for (int i = BITS_PER_CHAR - 1; i >= 0; --i) {
            char dataByte;
            file.read(&dataByte, 1);

            if (file.eof()) {
                endOfFile = true;
                break;
            }

            // Extract LSB and store in bitset
            decryptedByte[i] = dataByte & 1;
        }

        if (endOfFile)
            break;

        std::uint8_t decodedValue = static_cast<std::uint8_t>(decryptedByte.to_ulong());
        if (decodedValue == 0)
            break;

        decodedValues.push_back(decodedValue);
    }
    file.close();

    // Decode the message and print it
    std::string decodedMessage = endOfFile or decodedValues.empty() ?
            "No messages were found." :
            "Decrypted message is: " + pjc::text::decodeMessage(decodedValues);
    fmt::println("{}", decodedMessage);
}

/*
 * @brief Checks if the specified message can be embedded in the given file
 *
 * Steps:
 * 1. Calculates the number of characters in the message
 * 2. Calculates the number of bytes in the image's pixel map that can be used for embedding
 * 3. Checks permissions to write to the file to notify the user if no permissions
 * 4. Displays:
 *    4.1 Number of characters in the message
 *    4.2 Number of characters that can be encrypted
 *    4.3 Result message indicating whether the message can be embedded or not
 *
 * @param file_path Path to a file
 * @param message   Message to embed
*/
void check(const fs::path& file_path, const std::string& message) {
    size_t charsInMsg = pjc::text::charsInMessage(message);
    size_t encodableCharCount = pjc::image::countEncodableChars(file_path);

    std::string permsToWriteMsg;
    if ((fs::status(file_path).permissions() & fs::perms::owner_write) == fs::perms::none)
         permsToWriteMsg = "\nThere are NO permissions to write to that file.";

    std::string resultMsg = charsInMsg > encodableCharCount ?
        "So, your message is too long."+permsToWriteMsg : "So, your message can be encoded."+permsToWriteMsg;

    fmt::println(
        "=-=- Check Section -=-="
         "\nYour message is {} characters long."
         "\nIt is possible to encrypt {} characters."
         "\n{}\n"
        "=-=- End of Check Section -=-=",
        charsInMsg,
        encodableCharCount,
        resultMsg
    );
}

/*
 * @brief Displays the help section, providing guidelines
 *
 * Steps:
 * 1. Display supported image file extensions
 * 2. Provide usage instructions for each flag
 * 3. List flag names and their aliases
 *
*/
void help() {
    // Supported image file extensions
    fmt::println(
            "=-=- Image Steganography Help Section -=-="
            "\nSupported Image File Extensions:\n"
            " {}\n"
            " {}\n",
            EXT_PPM,
            EXT_BMP
    );

    // Usage instructions for each flag
    fmt::println(
            "\nUsage instructions:\n"
            " -i file_path            : Displays information about the specified file.\n"
            " -e file_path \"message\"  : Opens the image and embeds the specified message.\n"
            " -d file_path            : Opens the image and extracts the embedded message.\n"
            " -c file_path \"message\"  : Checks if the specified message can be embedded in the given file.\n"
            " -h                      : Displays this help section.\n"
            " -s                      : Shows supported characters for encoding.\n"
            " -1                      : Closes the program.\n"
    );

    // Flag names and their aliases
    fmt::println(
            "\nFlag name\tFlag Alias:\n"
            " -i          --info\n"
            " -e          --encrypt\n"
            " -d          --decrypt\n"
            " -c          --check\n"
            " -h          --help\n"
            " -s          --supported\n"
            "=-=- End of Help Section -=-="
    );
}

/*
 * @brief Prints the table of supported characters for encoding
 *
 * Steps:
 * 1. Print 32 characters in each row
 * 2. Print the total number of supported characters
 *
*/
void printSupportedChars() {
    // Get the map of supported characters for encoding
    const auto& map = pjc::text::getSupportedChars();

    fmt::println("=-=- Supported Chars For Encoding -=-=");

    std::uint8_t counter = 0;

    // Iterate through the map of supported characters
    for (const auto& pair : map) {
        fmt::print("{} ", pair.first);

        if (++counter % 32 == 0)
            fmt::println("");
    }

    // Print the total number of supported characters
    fmt::println("\nTotal number: {}", counter);

    fmt::println("=-=- End of Supported Chars Section -=-=");
}

/*
 * @brief Listens for inputs from the user, based on flags calls functions
 *
 * Steps:
 * 1. For every flag:
 *   1.1. Extract file path and message (if present)
 *   1.2. Check if file path and message (if present) are correct
 *   1.3. Call corresponding function based on the flag
 * 2. If none of the flags were matched, display an error message
 */
int main() {
    // Print welcome message and instructions
    fmt::println("Welcome to the Image Steganography Tool.\n"
                 "For detailed instructions and usage guidelines, please use the -h option.");

    std::string input;
    while (true) {
        // Get input from the user
        std::getline(std::cin, input);

        // Exit the program if input is '-1'
        if (input == "-1") {
            fmt::println("Closing the program...");
            std::exit(0);
        }

        // Define regex patterns for different flags
        std::string begPat = R"(\s*)";          // Beginning of the line
        std::string pathPat = R"(\s*([^\s]+))"; // File path pattern
        std::string msgPat = R"(\s*\"(.*)\")";  // Message pattern
        std::string endPat = R"(\s*$)";         // End of the line

        std::smatch regexMatch;

        // -i, --info flag
        if (std::regex_match(input, regexMatch,
        std::regex(begPat+R"((-i|--info))"+pathPat+endPat))) {
            auto file_path = fs::path(regexMatch[2].str());

            if (pjc::failure::isCorrectFilePath(file_path))
                info(file_path);
        }

        // -e, --encrypt flag
        else if (std::regex_match(input, regexMatch,
        std::regex(begPat+R"((-e|--encrypt))"+pathPat+msgPat+endPat))) {
            auto file_path = fs::path(regexMatch[2].str());
            auto message = regexMatch[3].str();

            if (pjc::failure::isCorrectFilePath(file_path) and
                pjc::failure::isCorrectMessage(file_path, message))
                    encrypt(file_path, message);
        }

        // -d, --decrypt flag
        else if (std::regex_match(input, regexMatch,
        std::regex(begPat+R"((-d|--decrypt))"+pathPat+endPat))) {
            auto file_path = fs::path(regexMatch[2].str());

            if (pjc::failure::isCorrectFilePath(file_path))
                decrypt(file_path);
        }

        // -c, --check flag
        else if (std::regex_match(input, regexMatch,
        std::regex(begPat+R"((-c|--check))"+pathPat+msgPat+endPat))) {
            auto file_path = fs::path(regexMatch[2].str());
            auto message = regexMatch[3].str();

            if (pjc::failure::isCorrectFilePath(file_path) and
                pjc::failure::isCorrectMessage(file_path, message))
                check(file_path, message);
        }

        // -h, --help flag
        else if (std::regex_match(input,
        std::regex(begPat+R"((-h|--help))"+endPat)))
            help();

        // -s, --supported flag
        else if (std::regex_match(input,
        std::regex(begPat+R"((-s|--supported))"+endPat)))
            printSupportedChars();

        // Empty input -> continue loop
        else if (std::regex_match(input, std::regex(begPat))) {}

        // Running without flags -> running with -h
        // (?!.*-).* - input does not contain dash
        else if (std::regex_match(input, std::regex(R"(^(?!.*-).*)"))) {
            fmt::println("No flags found, running -h");
            help();
        }

        // Incorrect flag usage
        else
            std::cerr << ("Incorrect flag usage\nUse -h for help.\n");
    }
}
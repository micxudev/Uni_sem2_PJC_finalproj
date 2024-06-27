**Image Steganography Project**
Overview
The Image Steganography project is a console application designed for embedding and extracting secret messages within image files. 
This tool modifies standard graphic files such as .BMP and .PPM, serving as mediums for hidden messages. 
The primary operations include writing a secret message to an image, reading a secret message from an image, 
and verifying the feasibility of writing or reading a message from a specific image file.

**Supported Formats**
.BMP
.PPM

**Functional Requirements**
The application supports several command-line operations, specified via flags. 
The available flags and their functions are:

-i <file_path>: Checks if the specified file path leads to a supported image format and displays information about the image, such as size, memory usage, and last modification timestamp.
-e <file_path> <"message">: Embeds the specified message into the image at the given file path. Proper error handling is required for unsupported file types.
-d <file_path>: Reads a hidden message from the specified image file. Error handling is necessary for unsupported file types.
-c <file_path> <"message">: Checks if the specified message can be embedded in the given image file or if a hidden message could exist.
-h: Displays information about the program, supported image file extensions, usage instructions, and specification of other flags.
_Running the program without any flags or with unsupported flags will display the help information equivalent to the -h flag._

**Implementation Details**
The project involves modifying individual image components to embed secret messages. 
This involves changing LSB (least significant bit) of each pixel, ensuring the alteration is imperceptible to the human eye. 

**Error Handling**
Unsupported file formats.
Insufficient permissions for file operations.
Incorrect or excessive command-line arguments.
File path errors or inaccessible files.

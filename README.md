<h1 align="center">
<strong>AUT_AP_2025_Spring Homework 5</strong>
</h1>

<p align="center">
<strong> Deadline: 12th of Ordibehesht - 23:59 o'clock</strong>
</p>

## Overview

In this homework, you will design and implement a simple messenger system in C++. The system will support different types of messages (such as text and voice), and will allow users to send messages to each other securely using RSA cryptography. You will use the provided `crypto.h` file for all cryptographic operations.

The question is divided into several parts:

1. **Message Hierarchy**: Implement a base `Message` class and derive `TextMessage` and `VoiceMessage` from it.
2. **User and Server Classes**: Implement the `User` and `Server` classes, which interact to send, receive, and store messages.
3. **Security**: All messages must be authenticated using RSA digital signatures.
4. **Cryptography**: Use the provided `crypto.h` interface for key generation, signing, and verification.

---

## Part 1: Message Hierarchy

### 1.1. The `Message` Class

All messages share some common properties. Define a base class `Message` with the following **private** member variables:

```cpp
class Message {
public:
    // (Member functions will be defined below)
private:
    std::string type;     // Type of the message ("text", "voice", ...)
    std::string sender;   // Username of the sender
    std::string receiver; // Username of the receiver
    std::string time;     // Creation time in GMT, format: "Sun Nov 13 17:50:43 2022"
};
```

#### Member Functions

You **must** implement the following member functions (you may add `const`, `override`, etc. as needed, but do not change the function signatures):

-   **Constructor**:  
    Assigns all member variables except `time`. The `time` variable should be set to the current GMT time in the format `"Sun Nov 13 17:50:43 2022"`. Use the `<ctime>` library for this.

    ```cpp
    Message(std::string type, std::string sender, std::string receiver);
    ```

-   **Default Constructor**:  
    Use constructor delegation to assign member variables.

    ```cpp
    Message();
    ```

-   **Getter Functions**:  
    Since all member variables are private, provide getter functions for each:

    ```cpp
    std::string get_type();
    std::string get_sender();
    std::string get_receiver();
    std::string get_time();
    ```

-   **Print Function**:  
    Prints the message details to an output stream.

    ```cpp
    void print(std::ostream &os);
    ```

    Example output:

    ```
    *************************
    david -> jenifer
    message type: text
    message time: Sun Nov 13 17:50:43 2022
    *************************
    ```

-   **Stream Insertion Operator**:  
    Overload the `<<` operator to print a `Message` using the `print` function.

    ```cpp
    std::ostream& operator<<(std::ostream &os, const Message &c);
    ```

**Question:**  
After implementing the derived classes, answer:  
_Why do you think we defined the `print` function and didn't implement everything in `operator<<` itself?_

---

### 1.2. The `TextMessage` Class

This class inherits from `Message` and adds a `text` member variable.

```cpp
class TextMessage : public Message {
public:
    // (Member functions will be defined below)
private:
    std::string text;
};
```

#### Member Functions

-   **Constructor**:  
    Assigns all member variables.

    ```cpp
    TextMessage(std::string text, std::string sender, std::string receiver);
    ```

-   **Print Function**:  
    Prints all message details, including the text.

    ```cpp
    void print(std::ostream &os);
    ```

    Example output:

    ```
    *************************
    david -> jenifer
    message type: text
    message time: Sun Nov 13 17:50:43 2022
    text: hello everybody
    *************************
    ```

-   **Getter for Text**:

    ```cpp
    std::string get_text();
    ```

---

### 1.3. The `VoiceMessage` Class

This class inherits from `Message` and adds a `voice` member variable, which is a vector of 5 random bytes.

```cpp
class VoiceMessage : public Message {
public:
    // (Member functions will be defined below)
private:
    std::vector<unsigned char> voice;
};
```

#### Member Functions

-   **Constructor**:  
    Assigns all member variables and fills `voice` with 5 random bytes.

    ```cpp
    VoiceMessage(std::string sender, std::string receiver);
    ```

-   **Print Function**:  
    Prints all message details, including the voice data as integers.

    ```cpp
    void print(std::ostream &os);
    ```

    Example output:

    ```
    *************************
    david -> jenifer
    message type: voice
    message time: Sun Nov 13 17:50:43 2022
    voice: 166 240 216 41 129
    *************************
    ```

-   **Getter for Voice**:

    ```cpp
    std::vector<unsigned char> get_voice();
    ```

---

## Part 2: User and Server Classes

The `User` and `Server` classes are tightly coupled. **Read all instructions before starting implementation.**

### 2.1. The `User` Class

Represents a user who can send messages. Each user has a username, a private key, and a pointer to the server.

```cpp
class User {
public:
    // (Member functions will be defined below)
private:
    std::string username;     // Username of the user
    std::string private_key;  // PEM-encoded private key
    Server* const server;     // Pointer to the server
};
```

#### Member Functions

-   **Constructor**:  
    Assigns all member variables.

    ```cpp
    User(std::string username, std::string private_key, Server* server);
    ```

-   **Getter for Username**:

    ```cpp
    std::string get_username();
    ```

-   **Send Text Message**:  
    Sends a text message to another user. Returns `true` if successful, `false` otherwise.  
    Use the `create_message` function of the `Server` class.

    ```cpp
    bool send_text_message(std::string text, std::string receiver);
    ```

-   **Send Voice Message**:  
    Sends a voice message (5 random bytes) to another user. Returns `true` if successful, `false` otherwise.  
    Use the `create_message` function of the `Server` class.

    ```cpp
    bool send_voice_message(std::string receiver);
    ```

---

### 2.2. The `Server` Class

Responsible for storing users, public keys, and messages.

```cpp
class Server {
public:
    // (Member functions will be defined below)
private:
    std::vector<User> users;                        // List of users
    std::map<std::string, std::string> public_keys; // Map: username -> public key
    std::vector<Message*> messages;                 // All messages sent
};
```

#### Member Functions

-   **Default Constructor**:

    ```cpp
    Server();
    ```

-   **Getter Functions**:

    ```cpp
    std::vector<User> get_users();
    std::map<std::string, std::string> get_public_keys();
    std::vector<Message*> get_messages();
    ```

-   **Create User**:  
    Creates a new user with a unique username. If the username already exists, throw `std::logic_error`.  
    Generates an RSA key pair for the user. The private key is given to the user; the public key is stored in `public_keys`.

    ```cpp
    User create_user(std::string username);
    ```

-   **Create Message**:  
    Adds a message to the server. The sender must sign their username as a signature.  
    The server authenticates the signature before adding the message.

    ```cpp
    bool create_message(Message* msg, std::string signature);
    ```

-   **Get All Messages From**:  
    Returns all messages sent from a given username.  
    **You must use STL algorithms only (no loops).**

    ```cpp
    std::vector<Message*> get_all_messages_from(std::string username);
    ```

-   **Get All Messages To**:  
    Returns all messages sent to a given username.  
    **You must use STL algorithms only (no loops).**

    ```cpp
    std::vector<Message*> get_all_messages_to(std::string username);
    ```

-   **Get Chat**:  
    Returns all messages between two users (regardless of direction).  
    **You must use STL algorithms only (no loops).**

    ```cpp
    std::vector<Message*> get_chat(std::string user1, std::string user2);
    ```

-   **Sort Messages**:  
    Sorts a vector of messages by their creation time.  
    **You must use STL algorithms only (no loops).**

    ```cpp
    void sort_msgs(std::vector<Message*> msgs);
    ```

---

## Part 3: Cryptography

### Using the Provided `crypto.h` File

You are provided with a `crypto.h` file that contains all the cryptographic functions you need. **Do not implement your own cryptography!** Use these functions as described.

#### How to Generate RSA Key Pairs

```cpp
std::string public_key, private_key;
crypto::generate_key(public_key, private_key);
```

-   `public_key` and `private_key` will be PEM-encoded strings.

#### How to Sign and Verify Data

To **sign** a string (e.g., a username) with a private key:

```cpp
std::string signature = crypto::signMessage(private_key, "my data");
```

To **verify** a signature with a public key:

```cpp
bool authentic = crypto::verifySignature(public_key, "my data", signature);
```

-   Returns `true` if the signature is valid, `false` otherwise.

---

## Part 4: RSA Algorithm Explanation

### What is RSA?

RSA is a widely-used public-key cryptosystem that enables secure data transmission and digital signatures. It is based on the mathematical difficulty of factoring large integers.

#### How RSA Works

-   **Key Generation**:
    -   Each user generates a pair of keys: a public key (shared with others) and a private key (kept secret).
-   **Signing**:
    -   To prove a message is from a specific user, the user signs the message (or some data, like their username) with their private key.
-   **Verification**:
    -   Anyone with the user's public key can verify that the signature is valid and that the message was indeed signed by the owner of the private key.

#### Why Use RSA in This Question?

-   **Authentication**:
    -   Ensures that only the legitimate sender can send messages as themselves.
-   **Integrity**:
    -   Guarantees that the message has not been tampered with.

#### In Practice

-   When a user sends a message, they sign their username with their private key.
-   The server uses the sender's public key to verify the signature before accepting the message.

---

## Hints and Notes

-   **Random Bytes**: For `VoiceMessage`, use C++ random number generation to fill the `voice` vector with 5 random bytes.
-   **Time Formatting**: Use `std::time_t`, `std::gmtime`, and `std::strftime` to format the time string.
-   **STL Algorithms**: For filtering and sorting messages, use algorithms like `std::copy_if`, `std::sort`, etc.
-   **Memory Management**: Since `messages` is a vector of pointers, ensure you manage memory properly to avoid leaks.

---

## Provided: `crypto.h`

```cpp
// crypto.h
#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>

namespace crypto {

/*
 * Generate a 2048-bit RSA key pair.
 * public_key  <- PEM-encoded public key
 * private_key <- PEM-encoded private key
 */
void generate_key(std::string& public_key, std::string& private_key);

/*
 * Sign `data` using the PEM-encoded RSA private key.
 * Returns a Base64-encoded signature.
 */
std::string signMessage(const std::string& private_key,
                        const std::string& data);

/*
 * Verify a Base64-encoded signature over `data` using
 * the PEM-encoded RSA public key. Returns true if valid.
 */
bool verifySignature(const std::string& public_key, const std::string& data,
                     const std::string& signature);

}  // namespace crypto

#endif  // CRYPTO_H
```

---

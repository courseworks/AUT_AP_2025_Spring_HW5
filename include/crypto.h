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

#endif	// CRYPTO_H

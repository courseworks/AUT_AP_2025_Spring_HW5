// crypto.cpp
#include "crypto.h"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>  // Still needed for RSA_F4 definition, but not functions

#include <stdexcept>
#include <vector>

namespace crypto {

// --- Base64 helpers --------------------------------------------------------

static std::string base64Encode(const unsigned char* buf, size_t len) {
	BIO* b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO* mem = BIO_new(BIO_s_mem());
	BIO_push(b64, mem);
	BIO_write(b64, buf, static_cast<int>(len));
	// Explicitly ignore return value to silence warning
	(void)BIO_flush(b64);
	BUF_MEM* bptr = nullptr;
	BIO_get_mem_ptr(b64, &bptr);
	std::string out(bptr->data, bptr->length);
	BIO_free_all(b64);
	return out;
}

static std::vector<unsigned char> base64Decode(const std::string& in) {
	BIO* b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO* mem = BIO_new_mem_buf(in.data(), static_cast<int>(in.size()));
	BIO_push(b64, mem);
	// Allocate slightly more potentially, then resize
	std::vector<unsigned char> buf(in.size());
	int decoded = BIO_read(b64, buf.data(), static_cast<int>(buf.size()));
	BIO_free_all(b64);
	if (decoded < 0) {
		throw std::runtime_error("Base64 decode error");
	}
	// Cast to size_type after ensuring it's non-negative
	buf.resize(static_cast<std::vector<unsigned char>::size_type>(decoded));
	return buf;
}

// --- Key generation (OpenSSL 3.0+ compatible) -----------------------------

void generate_key(std::string& pub, std::string& pri) {
	EVP_PKEY* pkey = nullptr;
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
	if (!ctx) {
		throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
	}

	if (EVP_PKEY_keygen_init(ctx) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		throw std::runtime_error("EVP_PKEY_keygen_init failed");
	}

	// Set RSA key generation parameters (2048 bits)
	if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		throw std::runtime_error("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
	}

	// Generate the key
	if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		throw std::runtime_error("EVP_PKEY_keygen failed");
	}

	EVP_PKEY_CTX_free(ctx);	 // Context no longer needed

	// Write private key PEM
	BIO* bpri = BIO_new(BIO_s_mem());
	if (!PEM_write_bio_PrivateKey(bpri, pkey, nullptr, nullptr, 0, nullptr,
								  nullptr)) {
		BIO_free(bpri);
		EVP_PKEY_free(pkey);
		throw std::runtime_error("PEM_write_bio_PrivateKey failed");
	}
	BUF_MEM* ptr = nullptr;
	BIO_get_mem_ptr(bpri, &ptr);
	pri.assign(ptr->data, ptr->length);
	BIO_free(bpri);

	// Write public key PEM
	BIO* bpub = BIO_new(BIO_s_mem());
	if (!PEM_write_bio_PUBKEY(bpub, pkey)) {
		BIO_free(bpub);
		EVP_PKEY_free(pkey);
		throw std::runtime_error("PEM_write_bio_PUBKEY failed");
	}
	BIO_get_mem_ptr(bpub, &ptr);
	pub.assign(ptr->data, ptr->length);
	BIO_free(bpub);

	EVP_PKEY_free(pkey);  // Free the key structure
}

// --- Signing (No changes needed, already uses EVP) ------------------------

std::string signMessage(const std::string& private_key,
						const std::string& data) {
	// 1) Load private key
	BIO* bio = BIO_new_mem_buf(private_key.data(),
							   static_cast<int>(private_key.size()));
	// Use PEM_read_bio_PrivateKey for compatibility with various key types
	EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);
	if (!pkey) {
		throw std::runtime_error("Failed to load private key");
	}

	// 2) Create and init sign context
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	EVP_PKEY_CTX* pctx = nullptr;  // For potential algorithm parameters
	if (!ctx ||
		EVP_DigestSignInit(ctx, &pctx, EVP_sha256(), nullptr, pkey) != 1) {
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(ctx);
		throw std::runtime_error("EVP_DigestSignInit failed");
	}

	// 3) Sign
	if (EVP_DigestSignUpdate(ctx, data.data(), data.size()) != 1) {
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(ctx);
		throw std::runtime_error("EVP_DigestSignUpdate failed");
	}

	size_t siglen = 0;
	// First call gets the size
	if (EVP_DigestSignFinal(ctx, nullptr, &siglen) != 1) {
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(ctx);
		throw std::runtime_error("EVP_DigestSignFinal failed (size check)");
	}

	std::vector<unsigned char> sig(siglen);
	// Second call performs the signing
	if (EVP_DigestSignFinal(ctx, sig.data(), &siglen) != 1) {
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(ctx);
		throw std::runtime_error("EVP_DigestSignFinal failed (signing)");
	}
	// sig.resize(siglen); // Not needed if size is correct from first call

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);

	// 4) Base64 encode
	return base64Encode(sig.data(), sig.size());
}

// --- Verification (No changes needed, already uses EVP) -------------------

bool verifySignature(const std::string& public_key, const std::string& data,
					 const std::string& signature) {
	// 1) Load public key
	BIO* bio =
		BIO_new_mem_buf(public_key.data(), static_cast<int>(public_key.size()));
	EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);
	if (!pkey) {
		// Don't throw here, could be an invalid key format attempt
		// Let the verification fail naturally if key is bad
		// throw std::runtime_error("Failed to load public key");
		return false;
	}

	// 2) Prepare context
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	EVP_PKEY_CTX* pctx = nullptr;  // For potential algorithm parameters
	if (!ctx ||
		EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), nullptr, pkey) != 1) {
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(ctx);
		// Throw here as it's an internal setup error
		throw std::runtime_error("EVP_DigestVerifyInit failed");
	}

	// 3) Verify
	if (EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) != 1) {
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(ctx);
		throw std::runtime_error("EVP_DigestVerifyUpdate failed");
	}

	std::vector<unsigned char> sigbin;
	try {
		sigbin = base64Decode(signature);
	} catch (const std::runtime_error& e) {
		// If base64 decoding fails, signature is invalid
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(ctx);
		return false;
	}

	// EVP_DigestVerifyFinal returns 1 for success, 0 for failure, <0 for error
	int ok = EVP_DigestVerifyFinal(ctx, sigbin.data(), sigbin.size());

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);

	if (ok < 0) {
		// Treat OpenSSL internal errors during finalization as an exception
		throw std::runtime_error("EVP_DigestVerifyFinal failed");
	}

	return ok == 1;
}

}  // namespace crypto

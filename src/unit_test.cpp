#include <gtest/gtest.h>

#include <chrono>
#include <regex>
#include <sstream>
#include <thread>
#include <vector>

#include "crypto.h"
#include "message.h"
#include "server.h"
#include "user.h"

//--------------------------------------------------------------------
//  Message hierarchy
//--------------------------------------------------------------------

TEST(MessageTest, ConstructorAndGetters) {
	Message msg{"text", "alice", "bob"};

	EXPECT_EQ(msg.get_type(), "text");
	EXPECT_EQ(msg.get_sender(), "alice");
	EXPECT_EQ(msg.get_receiver(), "bob");

	// "Sun Nov 13 17:50:43 2022"  ==>  24 – 25 chars, day & month are 3‑letter
	// words
	const std::string time = msg.get_time();
	EXPECT_FALSE(time.empty());
	std::regex r{R"(^\w{3} \w{3} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4}$)"};
	EXPECT_TRUE(std::regex_match(time, r))
		<< "Time string '" << time
		<< "' is not in the expected asctime(…) format.";
}

TEST(MessageTest, StreamInsertionDelegatesToPrint) {
	Message msg{"text", "alice", "bob"};
	std::ostringstream oss;
	oss << msg;

	const std::string out = oss.str();
	EXPECT_NE(out.find("alice -> bob"), std::string::npos);
	EXPECT_NE(out.find("message type: text"), std::string::npos);
}

//--------------------------------------------------------------------
//  TextMessage specifics
//--------------------------------------------------------------------

TEST(TextMessageTest, GetterAndPrint) {
	TextMessage tm{"hello world", "alice", "bob"};

	EXPECT_EQ(tm.get_text(), "hello world");

	std::ostringstream oss;
	tm.print(oss);
	const std::string printed = oss.str();
	EXPECT_NE(printed.find("text: hello world"), std::string::npos);
}

//--------------------------------------------------------------------
//  VoiceMessage specifics
//--------------------------------------------------------------------

TEST(VoiceMessageTest, SizeAndPrint) {
	VoiceMessage vm{"alice", "bob"};

	const auto voice = vm.get_voice();
	EXPECT_EQ(voice.size(), 5u);

	// All values must be a single unsigned byte (0–255)
	for (unsigned char b : voice) {
		EXPECT_LE(b, static_cast<unsigned char>(255));
	}

	std::ostringstream oss;
	vm.print(oss);
	const std::string printed = oss.str();
	EXPECT_NE(printed.find("voice:"), std::string::npos);
}

//--------------------------------------------------------------------
//  Server & User cooperation
//--------------------------------------------------------------------

TEST(ServerUserTest, CreateUserUniquenessAndKeyStorage) {
	Server server;

	// First creation succeeds.
	User alice = server.create_user("alice");
	EXPECT_EQ(alice.get_username(), "alice");
	ASSERT_TRUE(server.get_public_keys().count("alice"));
	EXPECT_FALSE(server.get_public_keys().at("alice").empty());

	// Duplicate usernames must throw.
	EXPECT_THROW(server.create_user("alice"), std::logic_error);
}

TEST(ServerUserTest, SendTextAndVoiceMessages) {
	Server server;
	User alice = server.create_user("alice");
	User bob = server.create_user("bob");

	EXPECT_TRUE(alice.send_text_message("hi, Bob!", "bob"));
	EXPECT_TRUE(alice.send_voice_message("bob"));

	const auto &all = server.get_messages();
	ASSERT_EQ(all.size(), 2u);

	const Message *first = all[0];
	const Message *second = all[1];

	EXPECT_EQ(first->get_type(), "text");
	EXPECT_EQ(second->get_type(), "voice");

	const auto *txt = dynamic_cast<const TextMessage *>(first);
	ASSERT_NE(txt, nullptr);
	EXPECT_EQ(txt->get_text(), "hi, Bob!");
}

TEST(ServerUserTest, QueryHelpersReturnCorrectSubsets) {
	Server server;
	User alice = server.create_user("alice");
	User bob = server.create_user("bob");
	User carl = server.create_user("carl");

	alice.send_text_message("to Bob #1", "bob");
	bob.send_text_message("reply", "alice");
	alice.send_voice_message("bob");
	alice.send_text_message("to Carl", "carl");

	const auto from_alice = server.get_all_messages_from("alice");
	EXPECT_EQ(from_alice.size(), 3u);

	const auto to_bob = server.get_all_messages_to("bob");
	EXPECT_EQ(to_bob.size(), 2u);

	const auto chat_ab = server.get_chat("alice", "bob");
	EXPECT_EQ(chat_ab.size(), 3u);
}
#include <gtest/gtest.h>

#include <iostream>

#include "message.h"
#include "server.h"
#include "user.h"

int main(int argc, char **argv) {
	if (false)	// Set to false to run unit-tests
	{
		// Debug section: Place your debugging code here
	} else {
		::testing::InitGoogleTest(&argc, argv);
		std::cout << "RUNNING TESTS ..." << std::endl;
		int ret{RUN_ALL_TESTS()};
		if (!ret)
			std::cout << "<<<SUCCESS>>>" << std::endl;
		else
			std::cout << "FAILED" << std::endl;
	}
	return 0;
}
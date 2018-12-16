#include "gtest/gtest.h"

#include <stdio.h>

int main(int argc, char **argv) {
	setvbuf(stdout, NULL, _IONBF, 0);
    ::testing::InitGoogleTest(&argc, argv); 
    return RUN_ALL_TESTS();
}

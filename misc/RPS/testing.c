#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>



int main()
{
	struct tm time_struct = {0};
	time_struct.tm_year = 2024-1900;
	time_struct.tm_mon  = 10;
	time_struct.tm_mday = 30;
	time_struct.tm_hour = 9;
	time_struct.tm_min = 0;
	time_struct.tm_sec = 0;
	time_struct.tm_isdst = -1;

	time_t timestamp = timegm(&time_struct);

	if (timestamp == -1) {
		printf("Error converting time\n");
		return 1;
	}
	
	srand((unsigned int) timestamp);

	printf("time: %u\n", (unsigned int)timestamp);

	for (int i = 0; i < 5; i++) {
		printf("%d\n", rand() % 3);
	}

	return 0;
}

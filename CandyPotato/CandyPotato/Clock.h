#pragma once
#include <ctime>
#include <stdio.h>

class Clock {
private:
    clock_t START_TIMER;

public:
    Clock() {
        START_TIMER = clock();
    }
    clock_t getStartTimer(void) {
        return START_TIMER;
    }

    clock_t tic()
    {
        return START_TIMER = clock();
    }

    int toc()
    {
        int time = (int)(((double)clock() - (double)this->getStartTimer()) / (double)CLOCKS_PER_SEC);
        //printf("Elapsed time: %d\n", time);
        return time;
    }

};
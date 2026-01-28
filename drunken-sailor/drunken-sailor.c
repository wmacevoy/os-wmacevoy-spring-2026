#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

double prob_left = 0.2;
double prob_middle = 0.2;
double prob_right = 0.6;
double prob_min = 1e-6;
int steps = 5;

void init(int argc, char *argv[]);

double prob = 1.0;
int location = 0;
int step = 0;

void step_left() {
    prob *= prob_left;
    step += 1;
    location += -1;
}

void step_middle() {
    prob *= prob_middle;
    step += 1;
    location += 0;
}

void step_right() {
    prob *= prob_right;
    step += 1;
    location += 1;
}

int main(int argc, char *argv[]) {
    init(argc, argv);

    printf("prob,location\n");


    while (step < steps) {
        if (prob*prob_left > prob_min && fork() == 0) { step_left(); }
        else if (prob*prob_middle > prob_min && fork() == 0) { step_middle(); }
        else if (prob*prob_right > prob_min && fork() == 0) { step_right(); }
        else { return 0; }
    }

    printf("%4d,%lg\n", location, prob);
    return 0;
}

void init(int argc, char *argv[]) {
    for (int argi = 1; argi < argc; argi++) {
        {
            const char *arg = "--prob-left=";
            size_t len = strlen(arg);
            if (strncmp(argv[argi], arg, len) == 0) {
                prob_left = atof(argv[argi] + len);
                continue;
            }
        }
        {
            const char *arg = "--prob-middle=";
            size_t len = strlen(arg);
            if (strncmp(argv[argi], arg, len) == 0) {
                prob_middle = atof(argv[argi] + len);
                continue;
            }
        }
        {
            const char *arg = "--prob-right=";
            size_t len = strlen(arg);
            if (strncmp(argv[argi], arg, len) == 0) {
                prob_right = atof(argv[argi] + len);
                continue;
            }
        }
        {
            const char *arg = "--prob-min=";
            size_t len = strlen(arg);
            if (strncmp(argv[argi], arg, len) == 0) {
                prob_min = atof(argv[argi] + len);
                continue;
            }
        }
        {
            const char *arg = "--steps=";
            size_t len = strlen(arg);
            if (strncmp(argv[argi], arg, len) == 0) {
                steps = atoi(argv[argi] + len);
                continue;
            }
        }

        fprintf(stderr, "Unknown argument: %s\n", argv[argi]);
        exit(EXIT_FAILURE);
    }

    double rescale = 1.0 / (prob_left + prob_middle + prob_right);
    prob_left *= rescale;
    prob_middle *= rescale;
    prob_right *= rescale;

    printf("%s --prob-left=%lg --prob-middle=%lg --prob-right=%lg --steps=%d --prob-min=%lg\n",
        argv[0], prob_left, prob_middle, prob_right, steps, prob_min);
}


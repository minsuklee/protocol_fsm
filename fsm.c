//
// fsm.c
// FSM sample code
//
// Created by Minsuk Lee, 2014.11.1.
// Copyright (c) 2014. Minsuk Lee All rights reserved.
// see LICENSE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/errno.h>

#define TEST_FSM

#define NUM_STATE   3
#define NUM_EVENT   8

enum { F_CON, F_ACK, F_FIN, F_DATA };       // Packet Type
enum { wait_CON, CON_sent, CONNECTED };     // States

// Events
enum { RCV_CON, RCV_FIN, RCV_ACK, RCV_DATA, CONNECT, CLOSE, SEND, TIMEOUT };

char *pkt_name[] = { "F_CON", "F_ACK", "F_FIN", "F_DATA" };
char *st_name[] =  { "wait_CON", "CON_sent", "CONNECTED" };
char *ev_name[] =  { "RCV_CON", "RCV_FIN", "RCV_ACK", "RCV_DATA",
                     "CONNECT", "CLOSE",   "SEND",    "TIMEOUT"   };

struct state_action {           // Protocol FSM Structure
    void (* action)(void *p);
    int next_state;
};

struct p_event {                // Event Structure
    int event;
    void *data;
    int size;
};

#define MAX_DATA_SIZE   (500)
struct packet {                 // 503 Byte Packet to & from Simulator
    unsigned char type;
    unsigned short size;
    char data[MAX_DATA_SIZE];
};

int c_state = wait_CON;         // Initial State
volatile int timedout = 0;

static void timer_handler(int signum)
{
    printf("Timedout\n");
    timedout = 1;
}

static void timer_init(void)
{
    struct sigaction sa;

    memset (&sa, 0, sizeof (sa));
    sa.sa_handler = &timer_handler;
    sigaction(SIGALRM, &sa, NULL);
}

void set_timer(int sec)
{
    struct itimerval timer;

    timedout = 0;
    timer.it_value.tv_sec = sec;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = 0;   // Non Periodic timer
    timer.it_interval.tv_usec = 0;
    setitimer (ITIMER_REAL, &timer, NULL);
}
void send_packet(int flag, void *p, int size)
{
#ifdef TEST_FSM
    printf("SEND %s\n", pkt_name[flag]);
#else
    struct packet buf;

    buf.type = flag;
    if (size) {
        buf.size = size;
        memcpy(buf.data, p, (size > MAX_DATA_SIZE) ? MAX_DATA_SIZE : size);
    }
    //---> sendto() to SIMULATOR
#endif
}

static void report_connect(void *p)
{
    printf("Connected\n");
    set_timer(0);           // Stop Timer
    // Report connection made to upper layer
}

static void passive_con(void *p)
{
    send_packet(F_ACK, NULL, 0);
    report_connect(NULL);
}

static void active_con(void *p)
{
    send_packet(F_CON, NULL, 0);
    set_timer(3);
}

static void close_con(void *p)
{
    printf("Connection Closed\n");
    send_packet(F_FIN, NULL, 0);
    // Report Connected Closed to upper layer
}

static void send_data(void *p)
{
    printf("Send Data to peer %p\n", p);
    send_packet(F_DATA, ((struct p_event *)p)->data, ((struct p_event *)p)->size);
}

static void report_data(void *p)
{
    printf("Data Arrived %p\n", p);
    // Queue received data for upper layer user
}

struct state_action p_FSM[NUM_STATE][NUM_EVENT] = {
    // wait_CON state
    { { passive_con, CONNECTED }, { NULL, wait_CON },      { NULL, wait_CON },            { NULL, wait_CON },
      { active_con,  CON_sent },  { NULL, wait_CON },      { NULL, wait_CON },            { NULL, wait_CON } },

    // CON_sent state
    { { passive_con, CONNECTED }, { close_con, wait_CON }, { report_connect, CONNECTED }, { NULL,      CON_sent },
      { NULL,        CON_sent },  { close_con, wait_CON }, { NULL,           CON_sent },  { close_con, wait_CON } },

    // CONNECTED state
    { { NULL, CONNECTED },        { close_con, wait_CON }, { NULL,      CONNECTED },      { report_data, CONNECTED },
      { NULL, CONNECTED },        { close_con, wait_CON }, { send_data, CONNECTED },      { NULL,        CONNECTED } },
};

struct p_event *get_event(void)
{
    static struct p_event event;    // not thread-safe
 
#ifdef TEST_FSM
    char test_event[10];
    int i;

    while (scanf("%s", test_event) <= 0) {
        // scanf() returns error on signal (timer)
        if ((errno == EINTR) && timedout) {
            timedout = 0;
            i = TIMEOUT;
            goto got_it;
        }
    }
        
    for (i = 0; i < NUM_EVENT; i++)
        if (!strcasecmp(test_event, ev_name[i]))
            goto got_it;
    fprintf(stderr, "%s : BAD EVENT NAME\n", test_event);
    exit(1);
got_it:
    event.event = i;
    // No data
#else
    // Check if there is user command
    // Check Packet arrival by event_wait()
    //    if then, decode header to make event
    // Check if timer is timed-out
#endif
    return &event;
}

void
Protocol_Loop(void)
{
    struct p_event *eventp;

    timer_init();
    while (1) {
        printf("Current Stat = %s\n", st_name[c_state]);

        /* Step 0: Get Input Event */
        eventp = get_event();

        /* Step 1: Do Action */
        if (p_FSM[c_state][eventp->event].action)
            p_FSM[c_state][eventp->event].action(eventp->data);

        /* Step 2: Set Next State */
        c_state = p_FSM[c_state][eventp->event].next_state;
    }
}

int
main(int argc, char *argv[])
{
    // INITIALIZE USER THREAD
    // SIMULATOR_INITIALIZE

    Protocol_Loop();

    // SIMULATOR_CLOSE

    return 0;
}


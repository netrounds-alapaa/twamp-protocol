/*
 * Name: Emma Mirică
 * Project: TWAMP Protocol
 * Class: OSS
 * Email: emma.mirica@cti.pub.ro
 *
 * Source: server.c
 * Note: contains the TWAMP server implementation
 *
 */
#include <sys/types.h>
//#undef __FD_SETSIZE
//#define __FD_SETSIZE 4096
// The above needs to be hacked in sys/select.h (In Solaris and BSD, you don't
// need to hack system headers...
#include <sys/select.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <assert.h>

#include "twamp.h"

#define MAX_CLIENTS 3000
#define MAX_SESSIONS_PER_CLIENT 1
#define DEFAULT_TEST_PORT 20000
#define MAX_NR_SOCKETS 3000

typedef enum {
    kOffline = 0,
    kConnected,
    kConfigured,
    kTesting
} ClientStatus;

struct active_session {
    int socket;
    RequestSession req;
    uint32_t seq_nr;
};

struct client_info {
    ClientStatus status;
    int socket;
    struct sockaddr_in addr;
    int sess_no;
    struct timeval shutdown_time;
    struct active_session sessions[MAX_SESSIONS_PER_CLIENT];
};

struct client_info clients[MAX_CLIENTS];

int accept_count = 0;
static int fd_max = 0;
static int test_port = DEFAULT_TEST_PORT;
static int port_override = 0;
static enum Mode authmode = kModeUnauthenticated;
static int used_sockets = 0;
static fd_set read_fds;

/* Prints the help of the TWAMP server */
static void usage(char *progname)
{
    fprintf(stderr, "Usage: %s [options]\n", progname);
    fprintf(stderr, "\nWhere \"options\" are:\n\n");

    fprintf(stderr,
            "	-a authmode		Default is Unauthenticated\n"
            "	-p t_port		Custom TWAMP test port. Default port 2000 is used if not specified\n"
            "	-P c_port  		Custom TWAMP control port. Default port 862 is used if not specified\n"
            "	-h         		Print this help message and exits\n");
    return;
}

/* Parses the command line arguments for the server */
static int parse_options(char *progname, int argc, char *argv[])
{
    int opt, c_port;
    if (argc < 1 || argc > 5) {
        fprintf(stderr, "Wrong number of arguments for %s. Number of arguments - %d\n", progname, argc);
        return 1;
    }

    while ((opt = getopt(argc, argv, "a:p:P:h")) != -1) {
        switch (opt) {
        case 'a':
            /* For now only unauthenticated mode is supported */
            /* TODO: set authentication mode to the one from cmd line */
            authmode = kModeUnauthenticated;
            break;
        case 'p':
            /* Set custom test port if required*/
            test_port = atoi(optarg);
            if (test_port < 1024 || test_port > (65535))
                test_port = DEFAULT_TEST_PORT;
            break;
        case 'P':
            /* Set custom control port if required */
            c_port = atoi(optarg);
            if ((c_port > 1024 || c_port < 65535) && (c_port != test_port))
                port_override = c_port;
            break;
        case 'h':
        default:
            return 1;
        }
    }

    return 0;
}

/* The cleanup_client function will close every connection (TWAMP-Control ot
 * TWAMP-Test that this server has with the client defined by the client_infor
 * structure received as a parameter.
 */
static void cleanup_client(struct client_info *client)
{
    fprintf(stderr, "Cleanup client %s, socket %d\n", inet_ntoa(client->addr.sin_addr), client->socket);
    FD_CLR(client->socket, &read_fds);
    close(client->socket);
    used_sockets--;
    int i;
    for (i = 0; i < client->sess_no; i++)
        /* If socket is -1 the session has already been closed */
        if (client->sessions[i].socket > 0) {
            FD_CLR(client->sessions[i].socket, &read_fds);
            close(client->sessions[i].socket);
            client->sessions[i].socket = -1;
            client->sessions[i].seq_nr = 0;
            used_sockets--;
        }
    memset(client, 0, sizeof(struct client_info));
    client->status = kOffline;
}

/* The TWAMP server can only accept max_clients and it will recycle the
 * positions for the available clients.
 */
static int find_empty_client(struct client_info *clients, int max_clients)
{
    int i;
    for (i = 0; i < max_clients; i++)
        if (clients[i].status == kOffline)
        {
            return i;
        }

    return -1;
}

/* Sends a ServerGreeting message to the Control-Client after
 * the TCP connection has been established.
 */
static int send_greeting(uint8_t mode_mask, struct client_info *client)
{
    int socket = client->socket;
    int i;
    ServerGreeting greet;
    memset(&greet, 0, sizeof(greet));
    greet.Modes = authmode & mode_mask;

    for (i = 0; i < 16; i++)
        greet.Challenge[i] = rand() % 16;
    for (i = 0; i < 16; i++)
        greet.Salt[i] = rand() % 16;
    greet.Count = (1 << 12);

    int rv = send(socket, &greet, sizeof(greet), 0);
    if (rv < 0) {
        fprintf(stderr, "[%s] ", inet_ntoa(client->addr.sin_addr));
        perror("Failed to send ServerGreeting message");
        cleanup_client(client);
    } else {
        //printf("Sent ServerGreeting message to %s. Result %d\n",
        //       inet_ntoa(client->addr.sin_addr), rv);
    }
    return rv;
}

/* After a ServerGreeting the Control-Client should respond with a
 * SetUpResponse. This function treats this message
 */
static int receive_greet_response(struct client_info *client)
{
    int socket = client->socket;
    SetUpResponse resp;
    memset(&resp, 0, sizeof(resp));
    int rv = recv(socket, &resp, sizeof(resp), 0);
    if (rv <= 0) {
        fprintf(stderr, "[%s] ", inet_ntoa(client->addr.sin_addr));
        perror("Failed to receive SetUpResponse");
        cleanup_client(client);
    } else {
        //printf("Received SetUpResponse message from %s with mode %d. Result %d\n",
        //       inet_ntoa(client->addr.sin_addr), resp.Mode, rv);
    }
    return rv;
}

/* Sent a ServerStart message to the Control-Client to end
 * the TWAMP-Control session establishment phase
 */
static int send_start_serv(struct client_info *client, TWAMPTimestamp StartTime)
{
    int socket = client->socket;
    ServerStart msg;
    memset(&msg, 0, sizeof(msg));
    msg.Accept = kOK;
    msg.StartTime = StartTime;
    int rv = send(socket, &msg, sizeof(msg), 0);
    if (rv <= 0) {
        fprintf(stderr, "[%s] ", inet_ntoa(client->addr.sin_addr));
        perror("Failed to send ServerStart message");
        cleanup_client(client);
    } else {
        client->status = kConfigured;
        //printf("ServerStart message sent to %s\n",
        //       inet_ntoa(client->addr.sin_addr));
    }
    return rv;
}

/* Sends a StartACK for the StartSessions message */
static int send_start_ack(struct client_info *client)
{
    StartACK ack;
    memset(&ack, 0, sizeof(ack));
    ack.Accept = kOK;
    int rv = send(client->socket, &ack, sizeof(ack), 0);
    if (rv <= 0) {
        fprintf(stderr, "[%s] ", inet_ntoa(client->addr.sin_addr));
        perror("Failed to send StartACK message");
    } else{
        //printf("StartACK message sent to %s\n",
        //inet_ntoa(client->addr.sin_addr));
    }
    return rv;
}

/* This function treats the case when a StartSessions is received from the
 * Control-Client to start a number of TWAMP-Test sessions
 */
static int receive_start_sessions(struct client_info *client,
                                  StartSessions * req)
{
    int i;
    int rv = send_start_ack(client);
    if (rv <= 0)
        return rv;

    /* Now it can receive packets on the TWAMP-Test sockets */
    for (i = 0; i < client->sess_no; i++) {
        FD_SET(client->sessions[i].socket, &read_fds);
        if (fd_max < client->sessions[i].socket)
            fd_max = client->sessions[i].socket;
    }
    client->status = kTesting;
    return rv;
}

/* This functions treats the case when a StopSessions is received from
 * the Control-Client to end all the Test sessions.
 */
static int receive_stop_sessions(struct client_info *client,
                                 StopSessions * req)
{
    /* If a StopSessions message was received, it can still receive Test packets
     * until the timeout has expired */
    gettimeofday(&client->shutdown_time, NULL);
    return 0;
}

/* Computes the response to a RequestTWSession message */
static int send_accept_session(struct client_info *client, RequestSession * req)
{
    AcceptSession acc;
    memset(&acc, 0, sizeof(acc));

    /* Check if there are any slots available */
    if ((used_sockets < MAX_NR_SOCKETS) && (client->sess_no < MAX_SESSIONS_PER_CLIENT)) {
        int testfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (testfd < 0) {
            fprintf(stderr, "[%s] ", inet_ntoa(client->addr.sin_addr));
            perror("Error opening socket");
            return -1;
        }

        struct sockaddr_in local_addr;
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = INADDR_ANY;
        local_addr.sin_port = req->ReceiverPort;

        int check_time = CHECK_TIMES;
        while (check_time-- && bind(testfd, (struct sockaddr *)&local_addr,
                                    sizeof(struct sockaddr)) < 0)
            local_addr.sin_port = test_port;

        if (check_time > 0) {
            req->ReceiverPort = local_addr.sin_port;
            acc.Accept = kOK;
            acc.Port = req->ReceiverPort;
            client->sessions[client->sess_no].socket = testfd;
            client->sessions[client->sess_no].req = *req;
            client->sess_no++;
        } else {
            acc.Accept = kTemporaryResourceLimitation;
            acc.Port = 0;
        }

    } else {
        acc.Accept = kTemporaryResourceLimitation;
        acc.Port = 0;
    }

    int rv = send(client->socket, &acc, sizeof(acc), 0);
    return rv;
}

/* This function treats the case when a RequestTWSession is received */
static int receive_request_session(struct client_info *client,
                                   RequestSession * req)
{
    //printf("Received RequestTWSession from %s\n", inet_ntoa(client->addr.sin_addr));
    int rv = send_accept_session(client, req);
    if (rv <= 0) {
        fprintf(stderr, "[%s] ", inet_ntoa(client->addr.sin_addr));
        perror("Failed to send RequestTWSession accept");
    }
    return rv;
}

/* This function will receive a TWAMP-Test packet and will send a response. In
 * TWAMP the Session-Sender (in our case the Control-Client, meaning the
 * TWAMP-Client) is always sending TWAMP-Test packets and the Session-Reflector
 * (Server) is receiving TWAMP-Test packets.
 */
static int receive_test_message(struct client_info *client, int session_index)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    //static uint32_t seq_nr = 0;

    ReflectorUPacket pack_reflect;
    memset(&pack_reflect, 0, sizeof(pack_reflect));

    SenderUPacket pack;
    memset(&pack, 0, sizeof(pack));

    int rv =
        recvfrom(client->sessions[session_index].socket, &pack, sizeof(pack), 0,
                 (struct sockaddr*) &addr, &len);

    pack_reflect.receive_time = get_timestamp();

    if (rv <= 0) {
        fprintf(stderr, "[%s] ", inet_ntoa(addr.sin_addr));
        perror("Failed to receive TWAMP-Test packet");
        return rv;
    } else if (rv < 14) {
        fprintf(stderr, "[%s] ", inet_ntoa(addr.sin_addr));
        perror("Short TWAMP-Test packet");
        return rv;
    }

    //printf("Received TWAMP-Test message from %s\n", inet_ntoa(addr.sin_addr));
    pack_reflect.seq_number = htonl(client->sessions[session_index].seq_nr++);
    pack_reflect.error_estimate = 0x100;  // Multiplier = 1
    pack_reflect.sender_seq_number = pack.seq_number;
    pack_reflect.sender_time = pack.time;
    pack_reflect.sender_error_estimate = pack.error_estimate;
    pack_reflect.sender_ttl = 255;      // Should be set by the Sender to 255

    addr.sin_port = client->sessions[session_index].req.SenderPort;

    pack_reflect.time = get_timestamp();

    if (rv < 41) {
        rv = sendto(client->sessions[session_index].socket, &pack_reflect, 41, 0,
                   (struct sockaddr*) &addr, sizeof(addr));
    }
    else {
        rv = sendto(client->sessions[session_index].socket, &pack_reflect, rv, 0,
                   (struct sockaddr*) &addr, sizeof(addr));
    }

    if (rv <= 0) {
        fprintf(stderr, "[%s] ", inet_ntoa(client->addr.sin_addr));
        perror("Failed to send TWAMP-Test packet");
    }
    return rv;
}

int main(int argc, char *argv[])
{
    //assert(sizeof(fd_set) == 512);
    printf("Modified select() fd setsize: %d\n", __FD_SETSIZE);
    printf("sizeof(fd_set) %lu", sizeof(fd_set));
    char *progname = NULL;
    srand(time(NULL));
    /* Obtain the program name without the full path */
    progname = (progname = strrchr(argv[0], '/')) ? progname + 1 : *argv;

    /* Parse options */
    if (parse_options(progname, argc, argv)) {
        usage(progname);
        exit(EXIT_FAILURE);
    }

    /* Obtain start server time in TWAMP format */
    TWAMPTimestamp StartTime = get_timestamp();
    int listenfd;

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        perror("Error opening socket");
        exit(EXIT_FAILURE);
    }

    int yes = 1, control_port;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
    {
        perror("Setting SO_REUSEADDR failed");
        exit(EXIT_FAILURE);
    }

    /* Set Server address and bind on the TWAMP port */
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    control_port = port_override ? port_override : SERVER_PORT;
    printf("Control port is %d\n", control_port);
    serv_addr.sin_port = htons(control_port);

    used_sockets++;
    if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr)) < 0) {
        perror("Error on binding");
        exit(EXIT_FAILURE);
    }

    /* Start listening on the TWAMP port for new TWAMP-Control connections */
    if (listen(listenfd, 128)) {
        perror("Error on listen");
        exit(EXIT_FAILURE);
    }

    printf("Listening on port %d\n", control_port);

    FD_ZERO(&read_fds);
    FD_SET(listenfd, &read_fds);
    fd_max = listenfd;

    memset(clients, 0, MAX_CLIENTS * sizeof(struct client_info));

    int newsockfd;
    struct sockaddr_in client_addr;
    fd_set tmp_fds;
    FD_ZERO(&tmp_fds);

    int rv;
    printf("FD_SETSIZE %d\n", FD_SETSIZE);
    while (1) {
        tmp_fds = read_fds;
        if (select(fd_max + 1, &tmp_fds, NULL, NULL, NULL) < 0) {
            perror("Error in select");
            close(listenfd);
            exit(EXIT_FAILURE);
        }

        /* If an event happened on the listenfd, then a new TWAMP-Control
         * connection is received */
        if (FD_ISSET(listenfd, &tmp_fds)) {
            uint32_t client_len = sizeof(client_addr);
            if ((newsockfd = accept(listenfd,
                                    (struct sockaddr *)&client_addr,
                                    &client_len)) < 0) {
                perror("Error in accept");
            } else {
                //printf("Accept count: %d, used sockets %d ", accept_count++, used_sockets);
                /* Add a new client if there are any slots available */
                int pos = find_empty_client(clients, MAX_CLIENTS);
                uint8_t mode_mask = 0;

                if (pos != -1) {
                    clients[pos].status = kConnected;
                    clients[pos].socket = newsockfd;
                    clients[pos].addr = client_addr;
                    clients[pos].sess_no = 0;
                    used_sockets++;
                    FD_SET(newsockfd, &read_fds);
                    if (newsockfd > fd_max)
                        fd_max = newsockfd;
                    mode_mask = 0xFF;
                }
                else
                {
                    fprintf(stderr, "---------NO FREE CLIENT SLOTS!!!");
                    exit(1);
                }
                rv = send_greeting(mode_mask, &clients[pos]);
            }
        }

        /* Receives other packets from the established TWAMP-Control sessions */
        uint8_t buffer[4096];
        int i, j;
        for (i = 0; i < MAX_CLIENTS; i++)
            /* It can only receive TWAMP-Control messages from Online clients */
            if (clients[i].status != kOffline)
                if (FD_ISSET(clients[i].socket, &tmp_fds)) {
                    switch (clients[i].status) {
                    case kConnected:
                        /* If a TCP session has been established and a
                         * ServerGreeting has been sent, wait for the
                         * SetUpResponse and finish the TWAMP-Control setup */
                        rv = receive_greet_response(&clients[i]);
                        if (rv > 0) {
                            rv = send_start_serv(&clients[i], StartTime);
                        }
                        break;
                    case kConfigured:
                        /* Reset the buffer to receive a new message */
                        memset(buffer, 0, 4096);
                        rv = recv(clients[i].socket, buffer, 4096, 0);
                        if (rv <= 0) {
                            cleanup_client(&clients[i]);
                            break;
                        }
                        /* Check the message received: It can only be
                         * StartSessions or RequestTWSession */
                        switch (buffer[0]) {
                        case kStartSessions:
                            rv = receive_start_sessions(&clients[i],
                                                        (StartSessions *)buffer);
                            break;
                        case kRequestTWSession:
                            rv = receive_request_session(&clients[i],
                                                         (RequestSession *)buffer);
                            break;
                        default:
                            break;
                        }

                        if (rv <= 0)
                            cleanup_client(&clients[i]);
                        break;
                    case kTesting:
                        // In this state can only receive a StopSessions msg
                        memset(buffer, 0, 4096);
                        //printf("waiting for stopsess, sock %d\n", clients[i].socket);
                        rv = recv(clients[i].socket, buffer, 4096, 0);
                        if (rv <= 0) {
                            cleanup_client(&clients[i]);
                            break;
                        }
                        if (buffer[0] == kStopSessions) {
                            rv = receive_stop_sessions(&clients[i],
                                                       (StopSessions *) buffer);
                        }
                        break;
                    default:
                        break;
                    }
                }

        /* Check for TWAMP-Test packets */
        for (i = 0; i < MAX_CLIENTS; i++) {
            struct timeval current;
            gettimeofday(&current, NULL);

            if (clients[i].status == kTesting) {
                uint8_t has_active_test_sessions = 0;
                for (j = 0; j < clients[i].sess_no; j++) {
                    rv = get_actual_shutdown(&current, &clients[i].shutdown_time,
                                             &clients[i].sessions[j].req.Timeout);
                    if (rv > 0) {
                        has_active_test_sessions = 1;
                        if (FD_ISSET(clients[i].sessions[j].socket, &tmp_fds)) {
                            rv = receive_test_message(&clients[i], j);
                        }
                    } else {
                        FD_CLR(clients[i].sessions[j].socket, &read_fds);
                        close(clients[i].sessions[j].socket);
                        used_sockets--;
                        clients[i].sessions[j].socket = -1;
                    }
                }
                if (!has_active_test_sessions) {
                    memset(&clients[i].shutdown_time, 0, sizeof(clients[i].shutdown_time));
                    clients[i].sess_no = 0;
                    clients[i].status = kConfigured;
                }
            }
        }
    }

    return 0;
}

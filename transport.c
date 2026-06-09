/*
 * transport.c 
 *
 * CS244a HW#3 (Reliable Transport)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"

/* Connection states */
enum {
    CSTATE_CLOSED = 0,
    CSTATE_LISTEN,
    CSTATE_SYN_SENT,
    CSTATE_SYN_RCVD,
    CSTATE_ESTABLISHED,
    CSTATE_FIN_WAIT_1,
    CSTATE_FIN_WAIT_2,
    CSTATE_CLOSE_WAIT,
    CSTATE_CLOSING,
    CSTATE_LAST_ACK,
    CSTATE_TIME_WAIT
};

#define STCP_FIXED_WINDOW 3072
#define DELAYED_ACK_TIMEOUT 100  /* 100ms in milliseconds */

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;
    
    /* Sender state */
    tcp_seq send_next;          /* Next sequence number to send */
    tcp_seq send_unack;         /* Oldest unacknowledged sequence number */
    size_t send_window;         /* Available send window */
    
    /* Receiver state */
    tcp_seq recv_next;          /* Next expected sequence number */
    bool_t ack_pending;         /* True if we need to send an ACK */
    
} context_t;

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
static void send_packet(mysocket_t sd, context_t *ctx, uint8_t flags, 
                       const void *data, size_t data_len);
static void send_ack(mysocket_t sd, context_t *ctx);

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);
    
    /* Initialize sender state */
    ctx->send_next = ctx->initial_sequence_num;
    ctx->send_unack = ctx->initial_sequence_num;
    ctx->send_window = STCP_FIXED_WINDOW;
    
    /* Initialize receiver state */
    ctx->recv_next = 0;  /* Will be set when we receive SYN */
    ctx->ack_pending = FALSE;
    
    ctx->done = FALSE;
    
    stcp_set_context(sd, ctx);

    if (is_active)
    {
        /* Active open (client) - send SYN */
        ctx->connection_state = CSTATE_SYN_SENT;
        send_packet(sd, ctx, TH_SYN, NULL, 0);
        ctx->send_next++;  /* SYN consumes one sequence number */
    }
    else
    {
        /* Passive open (server) - wait for SYN */
        ctx->connection_state = CSTATE_LISTEN;
    }

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
}

/* generate initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);
    ctx->initial_sequence_num = 1;
}

/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);

    while (!ctx->done)
    {
        unsigned int event;
        struct timespec timeout;
        struct timespec *timeout_ptr = NULL;
        
        /* Set up timeout for delayed ACK if needed */
        if (ctx->ack_pending && ctx->connection_state == CSTATE_ESTABLISHED)
        {
            struct timeval now;
            gettimeofday(&now, NULL);
            
            /* Calculate absolute timeout: current time + 100ms */
            timeout.tv_sec = now.tv_sec;
            timeout.tv_nsec = now.tv_usec * 1000;  /* Convert usec to nsec */
            
            /* Add 100 milliseconds */
            timeout.tv_nsec += DELAYED_ACK_TIMEOUT * 1000000L;  /* 100ms in nanoseconds */
            
            /* Handle nanosecond overflow */
            if (timeout.tv_nsec >= 1000000000L)
            {
                timeout.tv_sec++;
                timeout.tv_nsec -= 1000000000L;
            }
            
            timeout_ptr = &timeout;
        }

        /* Wait for event */
        event = stcp_wait_for_event(sd, ANY_EVENT, timeout_ptr);

        /* Handle timeout for delayed ACK */
        if (event == TIMEOUT && ctx->ack_pending)
        {
            send_ack(sd, ctx);
            ctx->ack_pending = FALSE;
        }

        /* Check if network data arrived */
        if (event & NETWORK_DATA)
        {
            char buffer[sizeof(STCPHeader) + STCP_MSS];
            ssize_t recv_len = stcp_network_recv(sd, buffer, sizeof(buffer));
            
            if (recv_len < (ssize_t)sizeof(STCPHeader))
            {
                continue;
            }
            
            STCPHeader *header = (STCPHeader *)buffer;
            size_t header_len = TCP_DATA_START(header);
            size_t data_len = recv_len - header_len;
            
            tcp_seq seq_num = ntohl(header->th_seq);
            tcp_seq ack_num = ntohl(header->th_ack);
            
            /* Handle different states during handshake and operation */
            
            /* LISTEN state - waiting for SYN */
            if (ctx->connection_state == CSTATE_LISTEN)
            {
                if (header->th_flags == TH_SYN)
                {
                    /* Received SYN, send SYN-ACK */
                    ctx->recv_next = seq_num + 1;
                    ctx->connection_state = CSTATE_SYN_RCVD;
                    send_packet(sd, ctx, TH_SYN | TH_ACK, NULL, 0);
                    ctx->send_next++;  /* SYN consumes one sequence number */
                }
                continue;
            }
            
            /* SYN_SENT state - waiting for SYN-ACK */
            if (ctx->connection_state == CSTATE_SYN_SENT)
            {
                if ((header->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))
                {
                    if (ack_num == ctx->send_next)
                    {
                        /* Received SYN-ACK, send ACK */
                        ctx->recv_next = seq_num + 1;
                        ctx->send_unack = ack_num;
                        ctx->connection_state = CSTATE_ESTABLISHED;
                        send_packet(sd, ctx, TH_ACK, NULL, 0);
                        stcp_unblock_application(sd);
                    }
                }
                continue;
            }
            
            /* SYN_RCVD state - waiting for final ACK */
            if (ctx->connection_state == CSTATE_SYN_RCVD)
            {
                if (header->th_flags == TH_ACK && ack_num == ctx->send_next)
                {
                    /* Received final ACK, connection established */
                    ctx->send_unack = ack_num;
                    ctx->connection_state = CSTATE_ESTABLISHED;
                    stcp_unblock_application(sd);
                }
                continue;
            }
            
            /* Handle data packets in ESTABLISHED state */
            if (data_len > 0 && seq_num == ctx->recv_next)
            {
                if (ctx->connection_state == CSTATE_ESTABLISHED)
                {
                    /* Pass data to application */
                    const void *data = buffer + header_len;
                    stcp_app_send(sd, data, data_len);
                    
                    /* Update recv_next */
                    ctx->recv_next += data_len;
                    
                    /* Implement delayed ACK */
                    if (ctx->ack_pending)
                    {
                        /* Second packet received - send cumulative ACK immediately */
                        send_ack(sd, ctx);
                        ctx->ack_pending = FALSE;
                    }
                    else
                    {
                        /* First packet - pend ACK and wait for timeout or next packet */
                        ctx->ack_pending = TRUE;
                    }
                }
            }
            
            /* Handle ACK for data we sent (but not if FIN is present - FIN handler deals with it) */
            if ((header->th_flags & TH_ACK) && !(header->th_flags & TH_FIN) && 
                ctx->connection_state == CSTATE_ESTABLISHED)
            {
                if (ack_num > ctx->send_unack)
                {
                    size_t acked_bytes = ack_num - ctx->send_unack;
                    ctx->send_unack = ack_num;
                    ctx->send_window += acked_bytes;
                    
                    if (ctx->send_window > STCP_FIXED_WINDOW)
                        ctx->send_window = STCP_FIXED_WINDOW;
                }
            }
            
            /* Handle ACK in closing states (but not if FIN is present) */
            if ((header->th_flags & TH_ACK) && !(header->th_flags & TH_FIN))
            {
                /* Handle state transitions for close */
                if (ctx->connection_state == CSTATE_FIN_WAIT_1)
                {
                    /* Our FIN was acknowledged */
                    ctx->connection_state = CSTATE_FIN_WAIT_2;
                }
                else if (ctx->connection_state == CSTATE_CLOSING)
                {
                    /* Final ACK in simultaneous close */
                    ctx->done = TRUE;
                }
                else if (ctx->connection_state == CSTATE_LAST_ACK)
                {
                    /* Our FIN was acknowledged in passive close */
                    ctx->done = TRUE;
                }
            }
            
            /* Handle FIN */
            if (header->th_flags & TH_FIN)
            {
                /* Handle ACK part of FINACK first if present */
                if (header->th_flags & TH_ACK)
                {
                    if (ack_num > ctx->send_unack)
                    {
                        size_t acked_bytes = ack_num - ctx->send_unack;
                        ctx->send_unack = ack_num;
                        ctx->send_window += acked_bytes;
                        
                        if (ctx->send_window > STCP_FIXED_WINDOW)
                            ctx->send_window = STCP_FIXED_WINDOW;
                    }
                }
                
                /* Update recv_next to account for FIN (FIN consumes 1 seq number) */
                ctx->recv_next = seq_num + 1;
                
                /* Notify application that peer closed */
                stcp_fin_received(sd);
                
                /* Handle state transitions */
                if (ctx->connection_state == CSTATE_ESTABLISHED)
                {
                    /* Passive close - received FIN first */
                    ctx->connection_state = CSTATE_CLOSE_WAIT;
                    send_ack(sd, ctx);
                }
                else if (ctx->connection_state == CSTATE_FIN_WAIT_1)
                {
                    /* Check if our FIN was also ACKed */
                    if (header->th_flags & TH_ACK && ack_num == ctx->send_next)
                    {
                        /* Our FIN was ACKed in same packet - go directly to TIME_WAIT */
                        ctx->connection_state = CSTATE_TIME_WAIT;
                        send_ack(sd, ctx);
                        ctx->done = TRUE;
                    }
                    else
                    {
                        /* Simultaneous close - FIN received but our FIN not ACKed yet */
                        ctx->connection_state = CSTATE_CLOSING;
                        send_ack(sd, ctx);
                    }
                }
                else if (ctx->connection_state == CSTATE_FIN_WAIT_2)
                {
                    /* Normal active close - we sent FIN, got ACK, now got their FIN */
                    ctx->connection_state = CSTATE_TIME_WAIT;
                    send_ack(sd, ctx);
                    ctx->done = TRUE;
                }
            }
        }

        /* Check if application has data to send */
        if ((event & APP_DATA) && ctx->connection_state == CSTATE_ESTABLISHED)
        {
            /* Keep sending data while we have window space */
            while (ctx->send_window > 0)
            {
                char buffer[STCP_MSS];
                size_t max_read = (ctx->send_window < STCP_MSS) ? 
                                 ctx->send_window : STCP_MSS;
                
                size_t received = stcp_app_recv(sd, buffer, max_read);
                
                if (received == 0)
                    break;
                
                send_packet(sd, ctx, TH_ACK, buffer, received);
                ctx->send_next += received;
                ctx->send_window -= received;
            }
        }

        /* Check if application requested close */
        if (event & APP_CLOSE_REQUESTED)
        {
            if (ctx->connection_state == CSTATE_ESTABLISHED)
            {
                /* Active close */
                ctx->connection_state = CSTATE_FIN_WAIT_1;
                send_packet(sd, ctx, TH_FIN | TH_ACK, NULL, 0);
                ctx->send_next++;  /* FIN consumes one sequence number */
            }
            else if (ctx->connection_state == CSTATE_CLOSE_WAIT)
            {
                /* Passive close - send our FIN */
                ctx->connection_state = CSTATE_LAST_ACK;
                send_packet(sd, ctx, TH_FIN | TH_ACK, NULL, 0);
                ctx->send_next++;
            }
        }
    }
}

/* Send a packet with specified flags and data */
static void send_packet(mysocket_t sd, context_t *ctx, uint8_t flags, 
                       const void *data, size_t data_len)
{
    STCPHeader header;
    memset(&header, 0, sizeof(header));
    
    header.th_seq = htonl(ctx->send_next);
    header.th_ack = htonl(ctx->recv_next);
    header.th_off = sizeof(STCPHeader) / 4;
    header.th_flags = flags;
    header.th_win = htons(STCP_FIXED_WINDOW);
    
    if (data_len > 0)
    {
        stcp_network_send(sd, &header, sizeof(header), data, data_len, NULL);
    }
    else
    {
        stcp_network_send(sd, &header, sizeof(header), NULL);
    }
}

/* Send ACK packet */
static void send_ack(mysocket_t sd, context_t *ctx)
{
    send_packet(sd, ctx, TH_ACK, NULL, 0);
}

/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}
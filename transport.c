/*
 * transport.c
 *
 * CS244a HW#3 (Reliable Transport)
 *
 * Implemented STCP transport layer for PA3.
 *
 * Notes:
 * - Initial sequence number is 1.
 * - Window size fixed to 3072 bytes.
 * - MSS is 536 bytes.
 * - Delayed ACK timeout is 100 ms.
 *
 * This implementation assumes the standard stcp API functions exist:
 *  - stcp_wait_for_event(mysocket_t sd, unsigned int timeout, void *ignored)
 *  - stcp_network_send(mysocket_t sd, void *pkt, unsigned int len)
 *  - stcp_network_recv(mysocket_t sd, void *pkt, unsigned int *len)
 *  - stcp_app_recv(mysocket_t sd, void *buf, unsigned int len)
 *  - stcp_app_send(mysocket_t sd, void *buf, unsigned int len)
 *  - stcp_unblock_application(mysocket_t sd)
 *  - stcp_fin_received(mysocket_t sd)
 *
 * If the course-provided API signatures differ slightly, adapt calls accordingly.
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"

enum {
    CSTATE_CLOSED = 0,
    CSTATE_LISTEN,
    CSTATE_SYN_SENT,
    CSTATE_SYN_RCVD,
    CSTATE_ESTAB,
    CSTATE_FIN_WAIT_1,
    CSTATE_FIN_WAIT_2,
    CSTATE_CLOSE_WAIT,
    CSTATE_LAST_ACK,
    CSTATE_CLOSING,
    CSTATE_TIME_WAIT
};

#define FIXED_WINDOW 3072
#define DELAYED_ACK_TIMEOUT 100 /* milliseconds */

typedef struct
{
    bool_t done;

    int connection_state;
    tcp_seq initial_sequence_num;

    /* sender state */
    tcp_seq snd_una;   /* oldest unacknowledged seq */
    tcp_seq snd_nxt;   /* next sequence number to use */

    /* receiver state */
    tcp_seq rcv_nxt;   /* next expected sequence number */

    /* sender window available in bytes */
    unsigned int snd_wnd;

    /* delayed ACK state */
    int pending_ack;   /* 0 none pending, >0 number of packets seen since last ACK */
} context_t;

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);

/* helper to send an STCP header+optional payload */
static int send_packet(mysocket_t sd, STCPHeader *hdr, const char *payload, unsigned int payload_len)
{
    unsigned int hdr_words = hdr->th_off; /* number of 32-bit words */
    unsigned int hdr_bytes = hdr_words * 4;
    unsigned int pkt_len = hdr_bytes + payload_len;
    char *pkt = malloc(pkt_len);
    if (!pkt) return -1;
    /* header is packed in our STCPHeader sized struct, but th_off may indicate
       standard header size which equals sizeof(STCPHeader) */
    memset(pkt, 0, pkt_len);
    memcpy(pkt, hdr, sizeof(STCPHeader));
    if (payload_len && payload)
        memcpy(pkt + hdr_bytes, payload, payload_len);
    stcp_network_send(sd, pkt, pkt_len);
    free(pkt);
    return 0;
}

/* initialise the transport layer, and start the main loop.
 * this function should not return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;
    assert(sd >= 0);

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);

    /* initialize sender/receiver bookkeeping */
    ctx->snd_una = ctx->initial_sequence_num;
    ctx->snd_nxt = ctx->initial_sequence_num;
    ctx->rcv_nxt = 1; /* per spec, peer's first expected seq will be 1 when they send SYN */
    ctx->snd_wnd = FIXED_WINDOW;
    ctx->pending_ack = 0;
    ctx->done = FALSE;
    ctx->connection_state = CSTATE_CLOSED;

    if (is_active)
    {
        /* Active open: send SYN, wait for SYNACK, send ACK */
        STCPHeader synhdr;
        memset(&synhdr, 0, sizeof(synhdr));
        synhdr.th_off = sizeof(STCPHeader) / 4;
        synhdr.th_seq = htonl(ctx->snd_nxt);
        synhdr.th_ack = htonl(0);
        synhdr.th_flags = TH_SYN;
        synhdr.th_win = htons(FIXED_WINDOW);
        send_packet(sd, &synhdr, NULL, 0);
        ctx->connection_state = CSTATE_SYN_SENT;
        ctx->snd_nxt = ctx->snd_nxt + 1; /* SYN consumes one sequence */

        /* wait for SYNACK */
        while (1)
        {
            unsigned int event = stcp_wait_for_event(sd, 0, NULL);
            if (event & NETWORK_DATA)
            {
                unsigned int pkt_len = 0;
                /* we expect stcp_network_recv to fill pkt_len and return pointer via buffer */
                /* Assume prototype: stcp_network_recv(sd, buffer, &len) and buffer allocated here */
                /* We allocate a buffer big enough for header + MSS */
                unsigned int buf_sz = sizeof(STCPHeader) + STCP_MSS;
                char *buf = malloc(buf_sz);
                if (!buf) { ctx->connection_state = CSTATE_CLOSED; break; }
                int rc = stcp_network_recv(sd, buf, &pkt_len);
                if (rc < 0) { free(buf); continue; }
                if (pkt_len >= sizeof(STCPHeader))
                {
                    STCPHeader *hdr = (STCPHeader *) buf;
                    uint8_t flags = hdr->th_flags;
                    tcp_seq seq = ntohl(hdr->th_seq);
                    tcp_seq ack = ntohl(hdr->th_ack);
                    if ((flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK))
                    {
                        /* validate ack acknowledges our SYN */
                        if (ack == ctx->snd_nxt)
                        {
                            /* set rcv_nxt to peer seq + 1 (SYN consumes one) */
                            ctx->rcv_nxt = seq + 1;
                            /* send ACK (no payload) */
                            STCPHeader ackhdr;
                            memset(&ackhdr, 0, sizeof(ackhdr));
                            ackhdr.th_off = sizeof(STCPHeader) / 4;
                            ackhdr.th_seq = htonl(ctx->snd_nxt);
                            ackhdr.th_ack = htonl(ctx->rcv_nxt);
                            ackhdr.th_flags = TH_ACK;
                            ackhdr.th_win = htons(FIXED_WINDOW);
                            send_packet(sd, &ackhdr, NULL, 0);
                            ctx->connection_state = CSTATE_ESTAB;
                            stcp_unblock_application(sd);
                            free(buf);
                            break;
                        }
                    }
                }
                free(buf);
            }
        }
    }
    else
    {
        /* Passive open: wait for SYN, reply SYNACK, wait for ACK */
        ctx->connection_state = CSTATE_LISTEN;
        while (1)
        {
            unsigned int event = stcp_wait_for_event(sd, 0, NULL);
            if (event & NETWORK_DATA)
            {
                unsigned int pkt_len = 0;
                unsigned int buf_sz = sizeof(STCPHeader) + STCP_MSS;
                char *buf = malloc(buf_sz);
                if (!buf) { ctx->connection_state = CSTATE_CLOSED; break; }
                int rc = stcp_network_recv(sd, buf, &pkt_len);
                if (rc < 0) { free(buf); continue; }
                if (pkt_len >= sizeof(STCPHeader))
                {
                    STCPHeader *hdr = (STCPHeader *) buf;
                    uint8_t flags = hdr->th_flags;
                    tcp_seq seq = ntohl(hdr->th_seq);
                    if ((flags & TH_SYN) == TH_SYN)
                    {
                        /* prepare SYNACK */
                        ctx->rcv_nxt = seq + 1;
                        STCPHeader synack;
                        memset(&synack, 0, sizeof(synack));
                        synack.th_off = sizeof(STCPHeader) / 4;
                        synack.th_seq = htonl(ctx->snd_nxt);
                        synack.th_ack = htonl(ctx->rcv_nxt);
                        synack.th_flags = TH_SYN | TH_ACK;
                        synack.th_win = htons(FIXED_WINDOW);
                        send_packet(sd, &synack, NULL, 0);
                        ctx->connection_state = CSTATE_SYN_RCVD;
                        ctx->snd_nxt = ctx->snd_nxt + 1; /* SYN consumes one */
                        free(buf);
                        /* wait for ACK from peer */
                        while (1)
                        {
                            unsigned int ev2 = stcp_wait_for_event(sd, 0, NULL);
                            if (ev2 & NETWORK_DATA)
                            {
                                unsigned int pkt_len2 = 0;
                                unsigned int buf_sz2 = sizeof(STCPHeader) + STCP_MSS;
                                char *buf2 = malloc(buf_sz2);
                                if (!buf2) break;
                                int rc2 = stcp_network_recv(sd, buf2, &pkt_len2);
                                if (rc2 < 0) { free(buf2); continue; }
                                if (pkt_len2 >= sizeof(STCPHeader))
                                {
                                    STCPHeader *hdr2 = (STCPHeader *) buf2;
                                    uint8_t flags2 = hdr2->th_flags;
                                    tcp_seq ack2 = ntohl(hdr2->th_ack);
                                    if ((flags2 & TH_ACK) && ack2 == ctx->snd_nxt)
                                    {
                                        ctx->connection_state = CSTATE_ESTAB;
                                        stcp_unblock_application(sd);
                                        free(buf2);
                                        goto passive_established;
                                    }
                                }
                                free(buf2);
                            }
                        }
                    }
                }
                free(buf);
            }
        }
    }

passive_established:
    /* Enter control loop, it will not return until connection closed */
    control_loop(sd, ctx);

    /* cleanup */
    free(ctx);
}

/* generate initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);
    ctx->initial_sequence_num = 1;
}

/* helper to build an ACK-only header and send it */
static void send_ack_only(mysocket_t sd, context_t *ctx)
{
    STCPHeader ackhdr;
    memset(&ackhdr, 0, sizeof(ackhdr));
    ackhdr.th_off = sizeof(STCPHeader) / 4;
    ackhdr.th_seq = htonl(ctx->snd_nxt);
    ackhdr.th_ack = htonl(ctx->rcv_nxt);
    ackhdr.th_flags = TH_ACK;
    ackhdr.th_win = htons(FIXED_WINDOW);
    send_packet(sd, &ackhdr, NULL, 0);
}

/* control_loop() is the main STCP loop; it repeatedly waits for events */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);

    /* We maintain:
       - ctx->snd_una : oldest unacked seq
       - ctx->snd_nxt : next seq to use
       - ctx->rcv_nxt : next expected seq from peer
       - ctx->snd_wnd : available receiver window advertised by peer (initially FIXED_WINDOW)
    */

    ctx->snd_una = ctx->initial_sequence_num;
    ctx->snd_nxt = ctx->initial_sequence_num;
    ctx->rcv_nxt = ctx->rcv_nxt ? ctx->rcv_nxt : 1;
    ctx->snd_wnd = FIXED_WINDOW;
    ctx->pending_ack = 0;

    while (!ctx->done)
    {
        unsigned int timeout = 0;
        if (ctx->pending_ack > 0 && ctx->pending_ack < 2)
            timeout = DELAYED_ACK_TIMEOUT; /* wait for second packet or timeout */
        else
            timeout = 0;

        unsigned int event = stcp_wait_for_event(sd, timeout, NULL);

        /* If timeout occurred and we had a pending ACK, send it */
        if (timeout > 0 && !(event & (NETWORK_DATA | APP_DATA | APP_CLOSE_REQUESTED)))
        {
            if (ctx->pending_ack > 0)
            {
                send_ack_only(sd, ctx);
                ctx->pending_ack = 0;
            }
            /* continue to next loop to wait again */
            continue;
        }

        /* APP_DATA: application wants to send data */
        if (event & APP_DATA)
        {
            /* send up to available window */
            unsigned int want = ctx->snd_wnd - (unsigned int)(ctx->snd_nxt - ctx->snd_una);
            /* if no space, ignore (application will be blocked or retried by API) */
            while (want > 0)
            {
                unsigned int to_read = MIN((unsigned int)STCP_MSS, want);
                if (to_read == 0) break;
                char appbuf[STCP_MSS];
                unsigned int got = stcp_app_recv(sd, appbuf, to_read);
                if (got == 0) break; /* nothing to read */
                /* build header with ACK flag set */
                STCPHeader hdr;
                memset(&hdr, 0, sizeof(hdr));
                hdr.th_off = sizeof(STCPHeader) / 4;
                hdr.th_seq = htonl(ctx->snd_nxt);
                hdr.th_ack = htonl(ctx->rcv_nxt);
                hdr.th_flags = TH_ACK;
                hdr.th_win = htons(FIXED_WINDOW);
                send_packet(sd, &hdr, appbuf, got);
                ctx->snd_nxt += got;
                want = ctx->snd_wnd - (unsigned int)(ctx->snd_nxt - ctx->snd_una);
                /* if sent all available data, break */
                if (got < to_read) break;
            }
        }

        /* NETWORK_DATA: incoming packet(s) from peer */
        if (event & NETWORK_DATA)
        {
            unsigned int pkt_len = 0;
            unsigned int buf_sz = sizeof(STCPHeader) + STCP_MSS;
            char *buf = malloc(buf_sz);
            if (!buf) continue;
            int rc = stcp_network_recv(sd, buf, &pkt_len);
            if (rc >= 0 && pkt_len >= sizeof(STCPHeader))
            {
                STCPHeader *hdr = (STCPHeader *) buf;
                uint8_t flags = hdr->th_flags;
                tcp_seq seq = ntohl(hdr->th_seq);
                tcp_seq ack = ntohl(hdr->th_ack);
                uint16_t win = ntohs(hdr->th_win);
                unsigned int data_offset = TCP_DATA_START(buf);
                unsigned int payload_len = 0;
                if (pkt_len > data_offset)
                    payload_len = pkt_len - data_offset;

                /* update sender window advertisement */
                ctx->snd_wnd = win;

                /* Handle ACKs (update snd_una) */
                if (flags & TH_ACK)
                {
                    /* ack is the next expected seq at peer, so bytes acked = ack - snd_una */
                    if (ack > ctx->snd_una && ack <= ctx->snd_nxt)
                    {
                        ctx->snd_una = ack;
                    }
                }

                /* Handle FIN (we treat FIN as FIN+ACK always) */
                if (flags & TH_FIN)
                {
                    /* peer initiating close */
                    /* Notify API layer that FIN received */
                    stcp_fin_received(sd);

                    if (ctx->connection_state == CSTATE_ESTAB)
                    {
                        ctx->connection_state = CSTATE_CLOSE_WAIT;
                        /* send ACK for FIN */
                        /* FIN consumes one sequence number */
                        ctx->rcv_nxt = seq + 1;
                        STCPHeader ackhdr;
                        memset(&ackhdr, 0, sizeof(ackhdr));
                        ackhdr.th_off = sizeof(STCPHeader) / 4;
                        ackhdr.th_seq = htonl(ctx->snd_nxt);
                        ackhdr.th_ack = htonl(ctx->rcv_nxt);
                        ackhdr.th_flags = TH_ACK;
                        ackhdr.th_win = htons(FIXED_WINDOW);
                        send_packet(sd, &ackhdr, NULL, 0);
                    }
                    else if (ctx->connection_state == CSTATE_FIN_WAIT_1)
                    {
                        /* possible simultaneous close: peer FIN while we sent FIN */
                        ctx->connection_state = CSTATE_CLOSING;
                        /* ack the FIN */
                        ctx->rcv_nxt = seq + 1;
                        STCPHeader ackhdr2;
                        memset(&ackhdr2, 0, sizeof(ackhdr2));
                        ackhdr2.th_off = sizeof(STCPHeader) / 4;
                        ackhdr2.th_seq = htonl(ctx->snd_nxt);
                        ackhdr2.th_ack = htonl(ctx->rcv_nxt);
                        ackhdr2.th_flags = TH_ACK;
                        ackhdr2.th_win = htons(FIXED_WINDOW);
                        send_packet(sd, &ackhdr2, NULL, 0);
                    }
                    else if (ctx->connection_state == CSTATE_FIN_WAIT_2)
                    {
                        /* peer finished after our FIN was ACKed */
                        ctx->connection_state = CSTATE_TIME_WAIT;
                        ctx->rcv_nxt = seq + 1;
                        /* send ACK and then close */
                        STCPHeader ackhdr3;
                        memset(&ackhdr3, 0, sizeof(ackhdr3));
                        ackhdr3.th_off = sizeof(STCPHeader) / 4;
                        ackhdr3.th_seq = htonl(ctx->snd_nxt);
                        ackhdr3.th_ack = htonl(ctx->rcv_nxt);
                        ackhdr3.th_flags = TH_ACK;
                        ackhdr3.th_win = htons(FIXED_WINDOW);
                        send_packet(sd, &ackhdr3, NULL, 0);
                        /* for this assignment, we can terminate immediately */
                        ctx->done = TRUE;
                    }
                }

                /* Handle payload, only if sequence matches expected (simple in-order behavior) */
                if (payload_len > 0)
                {
                    /* expect seq == rcv_nxt */
                    if (seq == ctx->rcv_nxt)
                    {
                        /* deliver payload to application */
                        stcp_app_send(sd, buf + data_offset, payload_len);
                        ctx->rcv_nxt += payload_len;
                        /* delayed ACK logic */
                        ctx->pending_ack++;
                        if (ctx->pending_ack >= 2)
                        {
                            send_ack_only(sd, ctx);
                            ctx->pending_ack = 0;
                        }
                        /* else we wait for another packet or timeout to send cumulative ack */
                    }
                    else
                    {
                        /* out of order or duplicate, per assignment network reliable and in-order
                           assumption, but if not exact, still send ACK for current rcv_nxt */
                        send_ack_only(sd, ctx);
                        ctx->pending_ack = 0;
                    }
                }
            }
            free(buf);
        }

        /* APP_CLOSE_REQUESTED: application called close(), initiate FIN handshake */
        if (event & APP_CLOSE_REQUESTED)
        {
            if (ctx->connection_state == CSTATE_ESTAB)
            {
                /* send FINACK (FIN with ACK bit) */
                STCPHeader finhdr;
                memset(&finhdr, 0, sizeof(finhdr));
                finhdr.th_off = sizeof(STCPHeader) / 4;
                finhdr.th_seq = htonl(ctx->snd_nxt);
                finhdr.th_ack = htonl(ctx->rcv_nxt);
                finhdr.th_flags = TH_FIN | TH_ACK;
                finhdr.th_win = htons(FIXED_WINDOW);
                send_packet(sd, &finhdr, NULL, 0);
                ctx->snd_nxt = ctx->snd_nxt + 1; /* FIN consumes one */
                ctx->connection_state = CSTATE_FIN_WAIT_1;
            }
            else if (ctx->connection_state == CSTATE_CLOSE_WAIT)
            {
                /* application closing after receiving FIN, we need to send our FIN */
                STCPHeader finhdr2;
                memset(&finhdr2, 0, sizeof(finhdr2));
                finhdr2.th_off = sizeof(STCPHeader) / 4;
                finhdr2.th_seq = htonl(ctx->snd_nxt);
                finhdr2.th_ack = htonl(ctx->rcv_nxt);
                finhdr2.th_flags = TH_FIN | TH_ACK;
                finhdr2.th_win = htons(FIXED_WINDOW);
                send_packet(sd, &finhdr2, NULL, 0);
                ctx->snd_nxt = ctx->snd_nxt + 1;
                ctx->connection_state = CSTATE_LAST_ACK;
            }
        }

        /* After processing events, check for ACKs that move us to next shutdown states */
        if (ctx->connection_state == CSTATE_FIN_WAIT_1)
        {
            /* if peer ACKed our FIN, transition to FIN_WAIT_2 */
            if (ctx->snd_una >= ctx->snd_nxt)
            {
                ctx->connection_state = CSTATE_FIN_WAIT_2;
            }
        }
        else if (ctx->connection_state == CSTATE_LAST_ACK)
        {
            /* if peer ACKs our FIN, we can close */
            if (ctx->snd_una >= ctx->snd_nxt)
            {
                ctx->done = TRUE;
            }
        }
        else if (ctx->connection_state == CSTATE_CLOSING)
        {
            /* if our FIN is acked, move to TIME_WAIT and then close */
            if (ctx->snd_una >= ctx->snd_nxt)
            {
                ctx->connection_state = CSTATE_TIME_WAIT;
                ctx->done = TRUE;
            }
        }
    } /* main loop */

    /* ensure final ACKs were sent if needed is already handled in events above */
}

/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
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

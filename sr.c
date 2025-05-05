#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "emulator.h"
#include "gbn.h"

/* ******************************************************************
   Go Back N protocol.  Adapted from J.F.Kurose
   ALTERNATING BIT AND GO-BACK-N NETWORK EMULATOR: VERSION 1.2

   Network properties:
   - one way network delay averages five time units (longer if there
   are other messages in the channel for GBN), but can be larger
   - packets can be corrupted (either the header or the data portion)
   or lost, according to user-defined probabilities
   - packets will be delivered in the order in which they were sent
   (although some can be lost).

   Modifications:
   - removed bidirectional GBN code and other code not used by prac.
   - fixed C style to adhere to current programming style
   - added GBN implementation
**********************************************************************/

#define RTT  16.0       /* round trip time.  MUST BE SET TO 16.0 when submitting assignment */
#define WINDOWSIZE 6    /* the maximum number of buffered unacked packet
                          MUST BE SET TO 6 when submitting assignment */
#define SEQSPACE 12      /* the min sequence space for GBN must be at least windowsize + 1 */
#define NOTINUSE (-1)   /* used to fill header fields that are not being used */

/* generic procedure to compute the checksum of a packet.  Used by both sender and receiver
   the simulator will overwrite part of your packet with 'z's.  It will not overwrite your
   original checksum.  This procedure must generate a different checksum to the original if
   the packet is corrupted.
*/
int ComputeChecksum(struct pkt packet)
{
  int checksum = 0;
  int i;

  checksum = packet.seqnum;
  checksum += packet.acknum;
  for ( i=0; i<20; i++ )
    checksum += (int)(packet.payload[i]);

  return checksum;
}

bool IsCorrupted(struct pkt packet)
{
  if (packet.checksum == ComputeChecksum(packet))
    return (false);
  else
    return (true);
}


/********* Sender (A) variables and functions ************/
static bool acked[WINDOWSIZE]; 
static struct pkt buffer[WINDOWSIZE];  /* array for storing packets waiting for ACK */
static int windowfirst, windowlast;    /* array indexes of the first/last packet awaiting ACK */
static int windowcount;                /* the number of packets currently awaiting an ACK */
static int A_nextseqnum;               /* the next sequence number to be used by the sender */

/* called from layer 5 (application layer), passed the message to be sent to other side */
void A_output(struct msg message)
{
  struct pkt sendpkt;
  int i;

  /* if not blocked waiting on ACK */
  if ( windowcount < WINDOWSIZE) {
    if (TRACE > 1)
      printf("----A: New message arrives, send window is not full, send new messge to layer3!\n");

    /* create packet */
    sendpkt.seqnum = A_nextseqnum;
    sendpkt.acknum = NOTINUSE;
    for ( i=0; i<20 ; i++ )
      sendpkt.payload[i] = message.data[i];
    sendpkt.checksum = ComputeChecksum(sendpkt);

    /* put packet in window buffer */
    /* windowlast will always be 0 for alternating bit; but not for GoBackN */
    windowlast = (windowlast + 1) % WINDOWSIZE;
    buffer[windowlast] = sendpkt;
    acked[windowlast] = false;
    windowcount++;

    /* send out packet */
    if (TRACE > 0)
      printf("Sending packet %d to layer 3\n", sendpkt.seqnum);
    tolayer3 (A, sendpkt);

    /* start timer if first packet in window */
    if (windowcount == 1)
      starttimer(A,RTT);

    /* get next sequence number, wrap back to 0 */
    A_nextseqnum = (A_nextseqnum + 1) % SEQSPACE;
  }
  /* if blocked,  window is full */
  else {
    if (TRACE > 0)
      printf("----A: New message arrives, send window is full\n");
    window_full++;
  }
}

/* called from layer 3, when a packet arrives for layer 4
   In this practical this will always be an ACK as B never sends data.
*/
void A_input(struct pkt packet)
{
    int i;
  /* if received ACK is not corrupted */
    if (!IsCorrupted(packet)) {
        if (TRACE > 0)
            printf("----A: uncorrupted ACK %d is received\n",packet.acknum);
        total_ACKs_received++;

    /* check if individual packets has been ACKed */
        if (windowcount != 0) {
            int seqfirst = buffer[windowfirst].seqnum;
            int seqlast = buffer[windowlast].seqnum;
            /* check case when seqnum has and hasn't wrapped */
            if (((seqfirst <= seqlast) && (packet.acknum >= seqfirst && packet.acknum <= seqlast)) ||
                ((seqfirst > seqlast) && (packet.acknum >= seqfirst || packet.acknum <= seqlast))) {
            /* packet is a new ACK */
                if (TRACE > 0)
                    printf("----A: ACK %d is not a duplicate\n",packet.acknum);
                new_ACKs++;
                for (i = 0; i < windowcount; i++) {
                    int buffer_idx = (windowfirst + i) % WINDOWSIZE; /*calculate the index of the current packet in the window*/
                    if (buffer[buffer_idx].seqnum == packet.acknum && !acked[buffer_idx]) {
                        acked[buffer_idx] = true;
                        
                        while (windowcount > 0 && acked[windowfirst]) {
                            acked[windowfirst] = false; /* mark the first packet in the window as unacknowledged */
                            windowfirst = (windowfirst + 1) % WINDOWSIZE;
                            windowcount--;
                            stoptimer(A);

                            if (windowcount > 0)
                                starttimer(A, RTT); /*restart the timer for the next packet if the window is not empty*/
                        }
                        break;
                    }                  
                }
            }
        }
        else {
            if (TRACE > 0)
                printf ("----A: duplicate ACK received, do nothing!\n");
        }
    }
    else
        if (TRACE > 0)
            printf ("----A: corrupted ACK is received, do nothing!\n");
}

/* called when A's timer goes off */
void A_timerinterrupt(void)
{
  if (TRACE > 0)
        printf("----A: time out,resend packets!\n");

    if (TRACE > 0)
        printf ("---A: resending packet %d\n", (buffer[windowfirst]).seqnum);
    packets_resent++;
    tolayer3(A, buffer[windowfirst]);
    starttimer(A, RTT);
}


/* the following routine will be called once (only) before any other */
/* entity A routines are called. You can use it to do any initialization */
void A_init(void)
{
  /* initialise A's window, buffer and sequence number */
  int i;
  A_nextseqnum = 0;  /* A starts with seq num 0, do not change this */
  windowfirst = 0;
  windowlast = -1;   /* windowlast is where the last packet sent is stored.
		     new packets are placed in winlast + 1
		     so initially this is set to -1
		   */
  windowcount = 0;
  for (i = 0; i < WINDOWSIZE; i++){
    acked[i] = false;
  }
}



/********* Receiver (B)  variables and procedures ************/

static int expectedseqnum; /* the sequence number expected next by the receiver */
static int B_nextseqnum;   /* the sequence number for the next packets sent by B */
static struct pkt recvbuf[WINDOWSIZE];
static bool  recvd[WINDOWSIZE];

/* called from layer 3, when a packet arrives for layer 4 at B*/
void B_input(struct pkt packet)
{
    struct pkt sendpkt;
    int i;
    int buffer_idx;

    if (!IsCorrupted(packet)) {
        /* new delivery window, accounting for wrap‑around */
        int diff = (packet.seqnum - expectedseqnum + SEQSPACE) % SEQSPACE;
        if (diff < WINDOWSIZE) {
            if (TRACE > 0)
                printf("----B: packet %d is correctly received, send ACK!\n",packet.seqnum);
            packets_received++;

            /* buffer out‑of‑order or deliver if exactly expected */
            buffer_idx = packet.seqnum % WINDOWSIZE; /*get index of received packet in the buffer*/
            if (!recvd[buffer_idx]) {
                recvbuf[buffer_idx] = packet; /*store the packet in the buffer*/
                recvd[buffer_idx]   = true; /*Mark the packet as received*/
            }
            /* ACK every valid in‑window packet */
            sendpkt.acknum = packet.seqnum;

            /* now deliver any in‑sequence run starting at expectedseqnum */
            buffer_idx = expectedseqnum % WINDOWSIZE;
            while (recvd[buffer_idx]) {
                tolayer5(B, recvbuf[buffer_idx].payload); /*deliver the packet's payload to layer 5*/
                recvd[buffer_idx] = false;

                /* update state variables */
                expectedseqnum = (expectedseqnum + 1) % SEQSPACE;

                buffer_idx = expectedseqnum % WINDOWSIZE;
            }
        }
        else {
            /* check already-delivered window → ACK the packet again */
            int back = (expectedseqnum - packet.seqnum + SEQSPACE) % SEQSPACE;

            /* packet.seqnum in [rcv_base−WINDOWSIZE … rcv_base−1] */
            /* i.e. it’s a duplicate of something we already delivered */
            if (back > 0 && back <= WINDOWSIZE) {
                if (TRACE > 0)
                    printf("----B: packet %d is correctly received, send ACK!\n",packet.seqnum);
                packets_received++;
                sendpkt.acknum = packet.seqnum;
            }
        }
    }
    else {
        /* packet is corrupted or out of order resend last ACK */
        if (TRACE > 0)
            printf("----B: packet corrupted or not expected sequence number, resend ACK!\n");
        if (expectedseqnum == 0)
            sendpkt.acknum = SEQSPACE - 1;
        else
            sendpkt.acknum = expectedseqnum - 1;
    }
  /* build and send the ACK (keeping your alternating seqnum) */
    sendpkt.seqnum   = B_nextseqnum;
    B_nextseqnum     = (B_nextseqnum + 1) % 2;
    /* we don't have any data to send.  fill payload with 0's */
    for ( i=0; i<20 ; i++ )
        sendpkt.payload[i] = '0';
    sendpkt.checksum = ComputeChecksum(sendpkt);
    tolayer3(B, sendpkt);
}

/* the following routine will be called once (only) before any other */
/* entity B routines are called. You can use it to do any initialization */
void B_init(void)
{
    int i;
    expectedseqnum = 0;
    for(i = 0; i < WINDOWSIZE; i++){ 
      recvd[i] = false;
    }
    B_nextseqnum = 1;
}

/******************************************************************************
 * The following functions need be completed only for bi-directional messages *
 *****************************************************************************/

/* Note that with simplex transfer from a-to-B, there is no B_output() */
void B_output(struct msg message)
{
}

/* called when B's timer goes off */
void B_timerinterrupt(void)
{
}

